import sjcl from './sjcl';
function sign(data, secret, expiresIn = 0) {
    const { iv, salt, ct } = JSON.parse(sjcl.encrypt(secret, JSON.stringify({ data, iat: Date.now(), exp: expiresIn })));
    return `${iv}.${salt}.${ct}`;
}
function verify(token, secret) {
    try {
        const [iv, salt, ct] = token.split('.');
        token = JSON.stringify(Object.assign({ iv, salt, ct }, sjcl.defaults));
        const { data, iat, exp } = JSON.parse(sjcl.decrypt(secret, token));
        if (!exp || Date.now() > iat + exp)
            return data;
        throw new Error();
    }
    catch (_a) {
        throw new Error('Invalid token or secret!');
    }
}
export { sign, verify };
