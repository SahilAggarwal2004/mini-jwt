import sjcl from 'sjcl'

const defaults = { v: 1, iter: 10000, ks: 128, ts: 64, mode: "ccm", adata: "", cipher: "aes" }

function encrypt(secret: string, data: any, { expiresIn = 0 }: { expiresIn: number } = { expiresIn: 0 }): string {
    // @ts-ignore
    const { ct, iv, salt } = JSON.parse(sjcl.encrypt(secret, JSON.stringify({ data, iat: Date.now(), exp: expiresIn })))
    return `${ct}.${iv}.${salt}`
}

function decrypt(secret: string, token: string) {
    try {
        const [ct, iv, salt] = token.split('.')
        token = JSON.stringify({ ct, iv, salt, ...defaults })
        const { data, iat, exp } = JSON.parse(sjcl.decrypt(secret, token))
        if (!exp || Date.now() < iat + exp) return data
        throw new Error()
    } catch { throw new Error('Invalid token or secret!') }
}

export { encrypt, decrypt }