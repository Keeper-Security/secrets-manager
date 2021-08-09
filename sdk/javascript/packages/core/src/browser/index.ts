import {browserPlatform} from "./browserPlatform"
import {connectPlatform} from "../platform"
import {initialize} from '../keeper'

connectPlatform(browserPlatform)
initialize()

export * from '../keeper'
export * from './localConfigStorage'


