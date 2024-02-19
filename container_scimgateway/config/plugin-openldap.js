// =================================================================================
// File:    plugin-openldap.js
//
// Original Author:  Jarle Elshaug
// Author: Dan Cinnamon
//
// Purpose: A very non-production ready demo to show how Okta may manage a raw LDAP using the Okta on-premise provisioning agent.
//          It started as a copy of the out of box LDAP plugin, with much of the AD stuff removed, and some openldap bits added.
//          It has a configuration that assumes a base setup of LDAP from bitnami/openldap:latest docker container.


'use strict'

const ldap = require('ldapjs')

// mandatory plugin initialization - start
let ScimGateway = null
try {
  ScimGateway = require('scimgateway')
} catch (err) {
  ScimGateway = require('./scimgateway')
}
const scimgateway = new ScimGateway()
const pluginName = scimgateway.pluginName
// const configDir = scimgateway.configDir
const configFile = scimgateway.configFile
let config = require(configFile).endpoint
config = scimgateway.processExtConfig(pluginName, config) // add any external config process.env and process.file
scimgateway.authPassThroughAllowed = false // true enables auth passThrough (no scimgateway authentication). scimgateway instead includes ctx (ctx.request.header) in plugin methods. Note, requires plugin-logic for handling/passing ctx.request.header.authorization to be used in endpoint communication
// mandatory plugin initialization - end

const _serviceClient = {}

if (!config.map || !config.map.user) {
  scimgateway.logger.error(`${pluginName} map.user configuration is mandatory`)
  process.exit(1)
}

// =================================================
// getUsers
// =================================================
scimgateway.getUsers = async (baseEntity, getObj, attributes, ctx) => {
  //
  // "getObj" = { attribute: <>, operator: <>, value: <>, rawFilter: <>, startIndex: <>, count: <> }
  // rawFilter is always included when filtering
  // attribute, operator and value are included when requesting unique object or simpel filtering
  // See comments in the "mandatory if-else logic - start"
  //
  // "attributes" is array of attributes to be returned - if empty, all supported attributes should be returned
  // Should normally return all supported user attributes having id and userName as mandatory
  // id and userName are most often considered as "the same" having value = <UserID>
  // Note, the value of returned 'id' will be used as 'id' in modifyUser and deleteUser
  // scimgateway will automatically filter response according to the attributes list
  //
  const action = 'getUsers'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes}`)

  const result = {
    Resources: [],
    totalResults: null
  }

  if (attributes.length < 1) {
    for (const key in config.map.user) { // attributes = 'id,userName,attributes=profileUrl,entitlements,x509Certificates.value,preferredLanguage,addresses,displayName,timezone,name.middleName,roles,locale,title,photos,meta.location,ims,phoneNumbers,emails,meta.version,name.givenName,name.honorificSuffix,name.honorificPrefix,name.formatted,nickName,meta.created,active,externalId,meta.lastModified,name.familyName,userType,groups.value'
      if (config.map.user[key].mapTo) attributes.push(config.map.user[key].mapTo)
    }
  }
  const [attrs] = scimgateway.endpointMapper('outbound', attributes, config.map.user) // SCIM/CustomSCIM => endpoint attribute naming

  const method = 'search'
  const scope = 'sub'
  let base = config.entity[baseEntity].ldap.userBase
  let ldapOptions

  // start mandatory if-else logic
  // DANC- the original LDAP connector had a special use case for the id/username/externalId field.
  // We don't need quite as much logic on the id field. We just have an issue where we need to URI decode the id field if we see it.
  if (getObj.operator) {
    const decodedValue = getObj.attribute === 'id' ? decodeURIComponent(getObj.value) : getObj.value
 
    if (getObj.operator === 'eq' && getObj.attribute === 'group.value') {
      // optional - only used when groups are member of users, not default behavior - correspond to getGroupUsers() in versions < 4.x.x
      throw new Error(`${action} error: not supporting groups member of user filtering: ${getObj.rawFilter}`)
    } else {
      // optional - simple filtering
      if (getObj.operator === 'eq') {
        const [ldapSearchAttr, err] = scimgateway.endpointMapper('outbound', getObj.attribute, config.map.user) // e.g. 'userName' => 'sAMAccountName'
        if (err) throw new Error(`${action} error: ${err.message}`)
        ldapOptions = {
          filter: `&${getObjClassFilter(baseEntity, 'user')}(${ldapSearchAttr}=${decodedValue})`, //DANC- in the main method- the GET call decodes, but PUT doesn't.  The PUT endpoint calls this, and fails to decode.
          scope: scope,
          attributes: attrs
        }
        if (config.entity[baseEntity].ldap.userFilter) ldapOptions.filter += config.entity[baseEntity].ldap.userFilter
      } else {
        throw new Error(`${action} error: not supporting simpel filtering: ${getObj.rawFilter}`)
      }
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
  } else {
    // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all users to be returned - correspond to exploreUsers() in versions < 4.x.x
    ldapOptions = {
      filter: `&${getObjClassFilter(baseEntity, 'user')}`,
      scope: scope,
      attributes: attrs
    }
    if (config.entity[baseEntity].ldap.userFilter) ldapOptions.filter += config.entity[baseEntity].ldap.userFilter
  }
  // end mandatory if-else logic

  if (!ldapOptions) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  try {
    const users = await doRequest(baseEntity, method, base, ldapOptions, ctx) // ignoring SCIM paging startIndex/count - get all
    result.totalResults = users.length
    result.Resources = await Promise.all(users.map(async (user) => { // Promise.all because of async map
      if (user.name) delete user.name // because mapper converts to SCIM name.xxx

      const scimObj = scimgateway.endpointMapper('inbound', user, config.map.user)[0] // endpoint attribute naming => SCIM
      if (!scimObj.groups) scimObj.groups = []
      return scimObj
    }))
  } catch (err) {
    throw new Error(`${action} error: ${err.message}`)
  }

  return result
}

// =================================================
// createUser
// =================================================
scimgateway.createUser = async (baseEntity, userObj, ctx) => {
  const action = 'createUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" userObj=${JSON.stringify(userObj)}`)

  let userBase = null
  if (userObj.entitlements && userObj.entitlements.userbase) { // override default userBase (type userbase will be lowercase)
    if (userObj.entitlements.userbase.value) {
      userBase = userObj.entitlements.userbase.value // temporary and not in config.map, will not be sent to endpoint
    }
  }
  if (!userBase) userBase = config.entity[baseEntity].ldap.userBase

  // convert SCIM attributes to endpoint attributes according to config.map
  const [endpointObj] = scimgateway.endpointMapper('outbound', userObj, config.map.user)
  // if (err) throw new Error(`${action} error: ${err.message}`)  // use above [endpointObj, err] to catch non supported attributes


  // endpointObj.objectClass is mandatory and must must match your ldap schema
  endpointObj.objectClass = config.entity[baseEntity].ldap.userObjectClasses // Active Directory: ["user", "person", "organizationalPerson", "top"]

  const method = 'add'
  const base = `${config.entity[baseEntity].ldap.userNamingAttr}=${userObj.userName},${userBase}`
  const ldapOptions = endpointObj

  try {
    await doRequest(baseEntity, method, base, ldapOptions, ctx)
    return null
  } catch (err) {
    const newErr = new Error(`${action} error: ${err.message}`)
    if (newErr.message.includes('ENTRY_EXISTS')) newErr.name += '#409' // customErrCode
    throw newErr
  }
}

// =================================================
// deleteUser - DANC - UNUSED
// =================================================
scimgateway.deleteUser = async (baseEntity, id, ctx) => {
  const action = 'deleteUser'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)

  const method = 'del'
  const ldapOptions = {}

  try {
    await doRequest(baseEntity, method, id, ldapOptions, ctx)
    return null
  } catch (err) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// modifyUser
// =================================================
scimgateway.modifyUser = async (baseEntity, id, attrObj, ctx) => {
  const action = 'modifyUser'

  //DANC Edit- for some reason the PUT method does not decodeURI like it does on GET- so we need to decode it here.
  const decodedId = decodeURIComponent(id)
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${decodedId} attrObj=${JSON.stringify(attrObj)}`)

  if (JSON.stringify(attrObj) === '{}') return null // only groups included

  // convert SCIM attributes to endpoint attributes according to config.map
  const [endpointObj] = scimgateway.endpointMapper('outbound', attrObj, config.map.user)
  // if (err) throw new Error(`${action} error: ${err.message}`)  // use above [endpointObj, err] to catch non supported attributes

  const method = 'modify'

  const ldapOptions = {
    operation: 'replace',
    modification: endpointObj
  }

  try {
    await doRequest(baseEntity, method, decodedId, ldapOptions, ctx)
    return null
  } catch (err) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// getGroups
// =================================================
scimgateway.getGroups = async (baseEntity, getObj, attributes, ctx) => {
  //
  // "getObj" = { attribute: <>, operator: <>, value: <>, rawFilter: <>, startIndex: <>, count: <> }
  // rawFilter is always included when filtering
  // attribute, operator and value are included when requesting unique object or simpel filtering
  // See comments in the "mandatory if-else logic - start"
  //
  // "attributes" is array of attributes to be returned - if empty, all supported attributes should be returned
  // Should normally return all supported group attributes having id, displayName and members as mandatory
  // id and displayName are most often considered as "the same" having value = <GroupName>
  // Note, the value of returned 'id' will be used as 'id' in modifyGroup and deleteGroup
  // scimgateway will automatically filter response according to the attributes list
  //
  const action = 'getGroups'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" getObj=${getObj ? JSON.stringify(getObj) : ''} attributes=${attributes}`)

  const result = {
    Resources: [],
    totalResults: null
  }

  if (!config.map.group || !config.entity[baseEntity].ldap.groupBase) { // not using groups
    scimgateway.logger.debug(`${pluginName}[${baseEntity}] "${action}" stopped - missing configuration endpoint.map.group or groupBase`)
    return result
  }

  //This is the same attribute add logic from the getUsers endpoint- that one worked, and the one that was here wasn't working.
  if (attributes.length < 1) {
    for (const key in config.map.group) { // attributes = 'id,userName,attributes=profileUrl,entitlements,x509Certificates.value,preferredLanguage,addresses,displayName,timezone,name.middleName,roles,locale,title,photos,meta.location,ims,phoneNumbers,emails,meta.version,name.givenName,name.honorificSuffix,name.honorificPrefix,name.formatted,nickName,meta.created,active,externalId,meta.lastModified,name.familyName,userType,groups.value'
      if (config.map.group[key].mapTo) attributes.push(config.map.group[key].mapTo)
    }
  }

  const [attrs] = scimgateway.endpointMapper('outbound', attributes, config.map.group) // SCIM/CustomSCIM => endpoint attribute naming

  const method = 'search'
  const scope = 'sub'
  let base = config.entity[baseEntity].ldap.groupBase
  let ldapOptions

  const [groupDisplayNameAttr, err1] = scimgateway.endpointMapper('outbound', 'displayName', config.map.group) // e.g. 'displayName' => 'cn'
  if (err1) throw new Error(`${action} error: ${err1.message}`)

  // mandatory if-else logic - start
  if (getObj.operator) {
    //As in the user search, we don't need all the other processing logic- we just want to run a search.
    if (getObj.operator === 'eq' && ['id', 'displayName', 'externalId'].includes(getObj.attribute)) {
      const decodedValue = decodeURIComponent(getObj.value)
      const [groupIdAttr, err] = scimgateway.endpointMapper('outbound', getObj.attribute, config.map.group) // e.g. 'userName' => 'sAMAccountName'
      ldapOptions = {
        filter: `&${getObjClassFilter(baseEntity, 'group')}(${groupIdAttr}=${decodedValue})`, // &(objectClass=group)(cn=Group1)
        scope: scope,
        attributes: attrs
      }
      if (config.entity[baseEntity].ldap.groupFilter) ldapOptions.filter += config.entity[baseEntity].ldap.groupFilter
    } else if (getObj.operator === 'eq' && getObj.attribute === 'members.value') {
      // mandatory - return all groups the user 'id' (getObj.value) is member of - correspond to getGroupMembers() in versions < 4.x.x
      // Resources = [{ id: <id-group>> , displayName: <displayName-group>, members [{value: <id-user>}] }]
      ldapOptions = 'getMemberOfGroups'
    } else {
      // optional - simpel filtering
      throw new Error(`${action} error: not supporting simpel filtering: ${getObj.rawFilter}`)
    }
  } else if (getObj.rawFilter) {
    // optional - advanced filtering having and/or/not - use getObj.rawFilter
    throw new Error(`${action} error: not supporting advanced filtering: ${getObj.rawFilter}`)
  } else {
  // mandatory - no filtering (!getObj.operator && !getObj.rawFilter) - all groups to be returned - correspond to exploreGroups() in versions < 4.x.x
    ldapOptions = {
      filter: `&${getObjClassFilter(baseEntity, 'group')}(${groupDisplayNameAttr}=*)`,
      scope: scope,
      attributes: attrs
    }
    if (config.entity[baseEntity].ldap.groupFilter) ldapOptions.filter += config.entity[baseEntity].ldap.groupFilter
  }
  // mandatory if-else logic - end

  if (!ldapOptions) throw new Error(`${action} error: mandatory if-else logic not fully implemented`)

  try {
    if (ldapOptions === 'getMemberOfGroups') result.Resources = await getMemberOfGroups(baseEntity, getObj.value, ctx)
    else {
      const groups = await doRequest(baseEntity, method, base, ldapOptions, ctx)
      result.Resources = await Promise.all(groups.map(async (group) => { // Promise.all because of async map
      return scimgateway.endpointMapper('inbound', group, config.map.group)[0] // endpoint attribute naming => SCIM
      }))
    }

    result.totalResults = result.Resources.length
    return result
  } catch (err) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// createGroup
// =================================================
scimgateway.createGroup = async (baseEntity, groupObj, ctx) => {
  const action = 'createGroup'
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" groupObj=${JSON.stringify(groupObj)}`)

  if (!config.map.group) throw new Error(`${action} error: missing configuration endpoint.map.group`)

  // convert SCIM attributes to endpoint attributes according to config.map

  //DANC - Stripping out the "display" attribute from the member attribute as we don't need it.
  if(groupObj.members) {
    for(var i = 0; i<groupObj.members.length; i++){
      if(groupObj.members[i].display) {
        delete groupObj.members[i].display
      }
    }
  }

  const [endpointObj, err] = scimgateway.endpointMapper('outbound', groupObj, config.map.group)
  if (err) throw new Error(`${action} error: ${err.message}`)

  // endpointObj.objectClass is mandatory and must must match your ldap schema
  endpointObj.objectClass = config.entity[baseEntity].ldap.groupObjectClasses // Active Directory: ["group"]
  
  //Cannot send in a null item for the member attribute.
  if(!groupObj.members || groupObj.members.length == 0) {
    endpointObj.member = ""
  }

  const method = 'add'
  const base = `${config.entity[baseEntity].ldap.groupNamingAttr}=${groupObj.displayName},${config.entity[baseEntity].ldap.groupBase}`
  const ldapOptions = endpointObj

  try {
    await doRequest(baseEntity, method, base, ldapOptions, ctx)
    return null
  } catch (err) {
    const newErr = new Error(`${action} error: ${err.message}`)
    if (newErr.message.includes('ENTRY_EXISTS')) newErr.name += '#409' // customErrCode
    throw newErr
  }
}

// =================================================
// deleteGroup
// =================================================
scimgateway.deleteGroup = async (baseEntity, id, ctx) => {
  const action = 'deleteGroup'
  const decodedId = decodeURIComponent(id)
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${id}`)

  if (!config.map.group) throw new Error(`${action} error: missing configuration endpoint.map.group`)
  const method = 'del'
  let base = decodedId // dn
  const ldapOptions = {}

  try {
    await doRequest(baseEntity, method, base, ldapOptions, ctx)
    return null
  } catch (err) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// modifyGroup
// =================================================
scimgateway.modifyGroup = async (baseEntity, id, attrObj, ctx) => {
  const action = 'modifyGroup'
  const decodedId = decodeURIComponent(id) // Need to decode the ID here since it's not handled upstream (only for GET method).
  scimgateway.logger.debug(`${pluginName}[${baseEntity}] handling "${action}" id=${decodedId} attrObj=${JSON.stringify(attrObj)}`)

  if (!config.map.group) throw new Error(`${action} error: missing configuration endpoint.map.group`)
  if (!attrObj.members) {
    throw new Error(`${action} error: only supports modification of members`)
  }
  if (!Array.isArray(attrObj.members)) {
    throw new Error(`${action} error: ${JSON.stringify(attrObj)} - correct syntax is { "members": [...] }`)
  }

  const [memberAttr, err1] = scimgateway.endpointMapper('outbound', 'members.value', config.map.group)
  if (err1) throw new Error(`${action} error: ${err1.message}`)

  const body = { add: { }, remove: { } }
  body.add[memberAttr] = []
  body.remove[memberAttr] = []

  for (let i = 0; i < attrObj.members.length; i++) {
    const el = attrObj.members[i]
    if (el.operation && el.operation === 'delete' && el.value) { // delete member from group
      body.remove[memberAttr].push(el.value) // endpointMapper returns URI encoded id because some IdP's don't encode id used in GET url e.g. Symantec/Broadcom/CA
    } else if(el.value) { // add member to group (if not null- we shouldn't have any additions of nulls here)
      body.add[memberAttr].push(el.value)
    }
  }

  const method = 'modify'
  let base = decodedId // dn

  try {
    if (body.add[memberAttr].length > 0) {
      const ldapOptions = { // using ldap lookup (dn) instead of search
        operation: 'add',
        modification: body.add
      }
      await doRequest(baseEntity, method, base, ldapOptions, ctx)
    }
    if (body.remove[memberAttr].length > 0) {
      const ldapOptions = { // using ldap lookup (dn) instead of search
        operation: 'delete',
        modification: body.remove
      }
      try { //DANC - In the delete request, we have an edge case where we remove the last member. In that case we need to resend with a blank member. openldap absolutely requires the member attribute to have something.
        await doRequest(baseEntity, method, base, ldapOptions, ctx)
      }
      catch(err) {
        scimgateway.logger.debug(`The error is: ${JSON.stringify(err)}`)
        if(err.lde_message == "Objectclass Violation") {
          scimgateway.logger.debug("Found last member- updating to set the member field to an empty array.")
          const ldapOptions = {
            operation: 'replace',
            modification: {"member": ""}
          }
          await doRequest(baseEntity, method, base, ldapOptions, ctx)
        } else {
          throw(err)
        }
      }
    }
    return null
  } catch (err) {
    throw new Error(`${action} error: ${err.message}`)
  }
}

// =================================================
// helpers
// =================================================

//
// getObjClassFilter returns object classes to be included in search
//
const getObjClassFilter = (baseEntity, type) => {
  let filter = ''
  switch (type) {
    case 'user':
      for (let i = 0; i < config.entity[baseEntity].ldap.userObjectClasses.length; i++) {
        filter += `(objectClass=${config.entity[baseEntity].ldap.userObjectClasses[i]})`
      }
      break
    case 'group':
      for (let i = 0; i < config.entity[baseEntity].ldap.groupObjectClasses.length; i++) {
        filter += `(objectClass=${config.entity[baseEntity].ldap.groupObjectClasses[i]})`
      }
      break
  }
  return filter
}

//
// getMemberOfGroups returns all groups the user is member of
// [{ id: <id-group>> , displayName: <displayName-group>, members [{value: <id-user>}] }]
//
const getMemberOfGroups = async (baseEntity, id, ctx) => {
  const action = 'getMemberOfGroups'
  if (!config.map.group) throw new Error('missing configuration endpoint.map.group') // not using groups

  let idDn = id
  if (config.useSID_id || config.useGUID_id) { // need dn
    const method = 'search'
    let base
    if (config.useSID_id) {
      const sid = convertStringToSid(id)
      if (!sid) throw new Error(`${action} error: ${id}=${id} - attribute having a none valid SID string`)
      base = `<SID=${sid}>`
    } else {
      const guid = Buffer.from(id, 'base64').toString('hex')
      base = `<GUID=${guid}>`
    }

    const ldapOptions = {
      attributes: ['dn']
    }

    try {
      const users = await doRequest(baseEntity, method, base, ldapOptions, ctx)
      if (users.length !== 1) throw new Error(`${action} error: did not find unique user having ${config.useSID_id ? 'objectSid' : 'objectGUID'} =${id}`)
      idDn = users[0].dn
    } catch (err) {
      const newErr = err
      throw newErr
    }
  }

  const attributes = ['id', 'displayName']
  const [attrs, err] = scimgateway.endpointMapper('outbound', attributes, config.map.group) // SCIM/CustomSCIM => endpoint attribute naming
  if (err) throw err
  const [memberAttr, err1] = scimgateway.endpointMapper('outbound', 'members.value', config.map.group)
  if (err1) throw err1

  const method = 'search'
  const scope = 'sub'
  const base = config.entity[baseEntity].ldap.groupBase

  const ldapOptions = {
    filter: `&${getObjClassFilter(baseEntity, 'group')}(${memberAttr}=${idDn})`,
    scope: scope,
    attributes: attrs
  }

  try {
    const groups = await doRequest(baseEntity, method, base, ldapOptions, ctx)
    return groups.map((grp) => {
      return { // { id: <id-group>> , displayName: <displayName-group>, members [{value: <id-user>}] }
        id: encodeURIComponent(grp[attrs[0]]), // not mandatory, but included anyhow
        displayName: grp[attrs[1]], // displayName is mandatory
        members: [{ value: encodeURIComponent(id) }] // only includes current user
      }
    })
  } catch (err) {
    const newErr = err
    throw newErr
  }
}

//
// getCtxAuth returns username/secret from ctx header when using Auth PassThrough
//
const getCtxAuth = (ctx) => { // eslint-disable-line
  if (!ctx?.request?.header?.authorization) return []
  const [authType, authToken] = (ctx.request.header.authorization || '').split(' ') // [0] = 'Basic' or 'Bearer'
  let username, password
  if (authType === 'Basic') [username, password] = (Buffer.from(authToken, 'base64').toString() || '').split(':')
  if (username) return [username, password] // basic auth
  else return [undefined, authToken] // bearer auth
}

//
// getServiceClient returns LDAP client used by doRequest
//
const getServiceClient = async (baseEntity, ctx) => {
  const action = 'getServiceClient'
  if (!config.entity[baseEntity].passwordDecrypted) config.entity[baseEntity].passwordDecrypted = scimgateway.getPassword(`endpoint.entity.${baseEntity}.password`, configFile)
  if (!config.entity[baseEntity].baseUrl) config.entity[baseEntity].baseUrl = config.entity[baseEntity].baseUrls[0] // failover logic also updates baseUrl

  if (!_serviceClient[baseEntity]) _serviceClient[baseEntity] = {}

  for (let i = -1; i < config.entity[baseEntity].baseUrls.length; i++) {
    try {
      const cli = await ldap.createClient({
        url: config.entity[baseEntity].baseUrl,
        connectTimeout: 5000,
        tlsOptions: {
          rejectUnauthorized: false
        },
        strictDN: false // false => allows none standard ldap base dn e.g. <SID=...> / <GUID=...>  ref. objectSid/objectGUID
      })
      await new Promise((resolve, reject) => {
        if (ctx?.request?.header?.authorization) { // using ctx authentication PassThrough
          const [username, password] = getCtxAuth(ctx)
          if (username) cli.bind(username, password, (err, res) => err ? reject(err) : resolve(res)) // basic auth
          else cli.bind(config.entity[baseEntity].username, password, (err, res) => err ? reject(err) : resolve(res)) // bearer token, using username from configuration
        } else cli.bind(config.entity[baseEntity].username, config.entity[baseEntity].passwordDecrypted, (err, res) => err ? reject(err) : resolve(res))
        cli.on('error', (err) => reject(err))
      })
      return cli // client OK
    } catch (err) {
      const retry = err.message.includes('timeout') || err.message.includes('ECONNREFUSED')
      if (retry && i + 1 < config.entity[baseEntity].baseUrls.length) { // failover logic
        scimgateway.logger.debug(`${pluginName}[${baseEntity}] baseUrl=${config.entity[baseEntity].baseUrl} connection error - starting retry`)
        config.entity[baseEntity].baseUrl = config.entity[baseEntity].baseUrls[i + 1]
      } else {
        if (err.message.includes('AcceptSecurityContext')) err.message = 'LdapErr: connect failure, invalid user/password'
        throw err
      }
    }
  }
  throw new Error(`${action} logic failed for some odd reasons - should not happend...`)
}

//
// doRequest - execute LDAP request
//
// method: "search" or "modify"
// base: <baseDN>
// ldapOptions: according to ldapjs module
// e.g.: {
//         "filter": "&(objectClass=user)(sAMAccountName=*)",
//         "scope": "sub",
//         "attributes": ["sAMAccountName","displayName","mail"]
//       }
//
const doRequest = async (baseEntity, method, base, ldapOptions, ctx) => {
  let result = null
  let client = null

  const options = scimgateway.copyObj(ldapOptions)

  try {
    client = await getServiceClient(baseEntity, ctx)
    switch (method) {
      case 'search':
        options.paged = { pageSize: 200, pagePause: false } // parse entire directory calling 'page' method for each page
        result = await new Promise((resolve, reject) => {
          const results = []
          client.search(base, scimgateway.copyObj(options), (err, search) => {
            if (err) {
              return reject(err)
            }

            search.on('searchEntry', (entry) => {
              if (!entry.pojo || !entry.pojo.attributes) return
              const obj = { dn: entry.pojo.objectName }
              entry.pojo.attributes.map((el) => {
                if (el.values.length > 1) obj[el.type] = el.values
                else obj[el.type] = el.values[0]
                return null
              })
             
              results.push(obj)
            })

            search.on('page', (entry, cb) => {
              // if (cb) cb() // pagePause = true gives callback
            })

            search.on('error', (err) => {
              if (err.message.includes('LdapErr: DSID-0C0909F2') || err.message.includes('NO_OBJECT')) return resolve([]) // object not found when using base <SID=...> or <GUID=...> ref. objectSid/objectGUID
              reject(err)
            })

            search.on('end', (_) => { resolve(results) })
          })
        })
        break

      case 'modify':
        result = await new Promise((resolve, reject) => {
          const dn = base
          const changes = []
          for (const key in options.modification) {
            const mod = {}
            mod.type = key
            if (Array.isArray(options.modification[key])) mod.values = options.modification[key]
            else {
              if (typeof options.modification[key] === 'string') mod.values = [options.modification[key]]
              else mod.values = [options.modification[key].toString()]
            }
            const change = new ldap.Change({
              operation: options.operation || 'replace',
              modification: mod // { type: "givenName", values: ["Joe"] }
            })
            changes.push(change)
          }
          client.modify(dn, changes, (err) => {
            if (err) {
              if (options.operation && options.operation === 'add' && options.modification && options.modification.member) {
                if (err.message.includes('ENTRY_EXISTS')) return resolve() // add already existing group to user
              }
              return reject(err)
            }
            resolve()
          })
        })
        break

      case 'add':
        result = await new Promise((resolve, reject) => {
          client.add(base, options, (err) => {
            if (err) {
              return reject(err)
            }
            resolve()
          })
        })
        break

      case 'del':
        result = await new Promise((resolve, reject) => {
          client.del(base, (err) => {
            if (err) {
              return reject(err)
            }
            resolve()
          })
        })
        break

      default:
        throw new Error('unsupported method')
    }
    client.unbind()
  } catch (err) {
    scimgateway.logger.error(`${pluginName}[${baseEntity}] doRequest method=${method} base=${base} ldapOptions=${JSON.stringify(options)} Error Response = ${err.message}`)
    if (client) {
      try { client.destroy() } catch (err) {}
    }
    throw err
  }

  scimgateway.logger.debug(`${pluginName}[${baseEntity}] doRequest method=${method} base=${base} ldapOptions=${JSON.stringify(options)} Response=${JSON.stringify(result)}`)
  return result
} // doRequest

//
// Cleanup on exit
//
process.on('SIGTERM', () => { // kill
})
process.on('SIGINT', () => { // Ctrl+C
})