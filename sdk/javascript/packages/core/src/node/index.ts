import {nodePlatform} from "./nodePlatform"
import {connectPlatform} from "../platform"
import {initialize} from '../keeper'

connectPlatform(nodePlatform)
initialize()

export * from '../keeper'
export * from '../platform'
export * from '../notation'
export {getTotpCode, generatePassword} from '../utils'
export * from './localConfigStorage'
