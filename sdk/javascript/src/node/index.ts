export * from '../keeper'

import {connectPlatform} from "../platform";
import {nodePlatform} from "./nodePlatform";

connectPlatform(nodePlatform);


