import {browserPlatform} from "./browserPlatform"
import {connectPlatform} from "../platform"
import {initialize} from '../keeper'

connectPlatform(browserPlatform)
initialize()

export * from '../keeper'
export {loadJsonConfig, inMemoryStorage} from '../platform'
export * from '../notation'
export {getTotpCode, generatePassword} from '../utils'
export * from './localConfigStorage'


