/**
 * Stands in for the platform in `ambient` mode: mints a token from kidp and writes it to a file,
 * the way a kubelet writes a projected service account token into a pod volume.
 *
 * The SDK never talks to the issuer in this mode - it only reads the file - so this script is the
 * whole "platform" half of the federated flow. In production this role belongs to kubelet, the cloud
 * metadata service, or a SPIFFE agent, and the KSM client is unaware any of it happened.
 *
 * Usage:
 *   npx ts-node internal/project-token.ts            # write one token and exit
 *   npx ts-node internal/project-token.ts --watch    # keep re-minting before each expiry
 *
 * The claims must satisfy the KA claim binding for this device (KSM_OAUTH_CLIENTS): kidp sets
 * sub = client_id, so CLIENT_ID below has to equal the binding's `sub`.
 */
import {request as httpRequest} from 'http'
import {promises as fs} from 'fs'

const TOKEN_ENDPOINT = 'http://localhost:8080/token'
const CLIENT_ID = 'ksm-demo'
const AUDIENCE = 'https://keepersecurity.com/api/rest/sm'
const TOKEN_PATH = 'ambient-token.jwt' // must match ambientTokenPath in quicktest-split.ts

// Re-mint this long before the token expires, so a reader never picks up an expired credential.
const REFRESH_MARGIN_SECONDS = 90

type TokenResponse = { access_token: string, expires_in?: number }

const mint = (): Promise<TokenResponse> => new Promise((resolve, reject) => {
    const body = new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: CLIENT_ID,
        audience: AUDIENCE
    }).toString()
    const post = httpRequest(TOKEN_ENDPOINT, {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body)}
    }, res => {
        const chunks: Buffer[] = []
        res.on('data', chunk => chunks.push(chunk))
        res.on('end', () => {
            const text = Buffer.concat(chunks).toString()
            if (res.statusCode !== 200) {
                reject(new Error(`token endpoint returned ${res.statusCode}: ${text}`))
                return
            }
            try {
                resolve(JSON.parse(text))
            } catch (e) {
                reject(e)
            }
        })
    })
    post.on('error', reject)
    post.end(body)
})

const claimsOf = (jwt: string): any =>
    JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString())

// Atomic replace: a reader must never see a half-written file. This is what kubelet does too.
const project = async (token: string): Promise<void> => {
    await fs.writeFile(`${TOKEN_PATH}.tmp`, token, {mode: 0o600})
    await fs.rename(`${TOKEN_PATH}.tmp`, TOKEN_PATH)
}

async function once(): Promise<number> {
    const response = await mint()
    await project(response.access_token)
    const claims = claimsOf(response.access_token)
    const lifetime = response.expires_in ?? (claims.exp - Math.floor(Date.now() / 1000))
    console.log(`projected ${TOKEN_PATH}: sub=${claims.sub} aud=${claims.aud} exp=+${lifetime}s`)
    return lifetime
}

async function main() {
    const watch = process.argv.includes('--watch')
    let lifetime = await once()
    if (!watch) {
        return
    }
    console.log(`watching - re-minting ${REFRESH_MARGIN_SECONDS}s before each expiry (ctrl-c to stop)`)
    while (true) {
        const delaySeconds = Math.max(lifetime - REFRESH_MARGIN_SECONDS, 10)
        await new Promise(resolve => setTimeout(resolve, delaySeconds * 1000))
        lifetime = await once()
    }
}

main().catch(e => {
    console.error(`${e.message} - is kidp running on ${TOKEN_ENDPOINT}?`)
    process.exit(1)
})
