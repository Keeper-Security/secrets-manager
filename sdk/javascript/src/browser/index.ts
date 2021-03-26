export * from '../keeper'

import {connectPlatform} from "../platform";
import {browserPlatform} from "./browserPlatform";

connectPlatform(browserPlatform);


