import { encrypt, decrypt } from 'sjcl';
const defaults = { v: 1, iter: 10000, ks: 128, ts: 64, mode: "ccm", adata: "", cipher: "aes" };
function sign(data, secret, expiresIn = 0) {
    const { ct, iv, salt } = JSON.parse(encrypt(secret, JSON.stringify({ data, iat: Date.now(), exp: expiresIn })));
    return `${ct}.${iv}.${salt}`;
}
function verify(token, secret) {
    try {
        const [ct, iv, salt] = token.split('.');
        token = JSON.stringify(Object.assign({ ct, iv, salt }, defaults));
        const { data, iat, exp } = JSON.parse(decrypt(secret, token));
        if (!exp || Date.now() > iat + exp)
            return data;
        throw new Error();
    }
    catch (_a) {
        throw new Error('Invalid token or secret!');
    }
}
export { sign, verify };
