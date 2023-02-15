"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verify = exports.sign = void 0;
const sjcl_1 = __importDefault(require("./sjcl"));
function sign(data, secret, expiresIn = 0) {
    const { iv, salt, ct } = JSON.parse(sjcl_1.default.encrypt(secret, JSON.stringify({ data, iat: Date.now(), exp: expiresIn })));
    return `${iv}.${salt}.${ct}`;
}
exports.sign = sign;
function verify(token, secret) {
    try {
        const [iv, salt, ct] = token.split('.');
        token = JSON.stringify(Object.assign({ iv, salt, ct }, sjcl_1.default.defaults));
        const { data, iat, exp } = JSON.parse(sjcl_1.default.decrypt(secret, token));
        if (!exp || Date.now() > iat + exp)
            return data;
        throw new Error();
    }
    catch (_a) {
        throw new Error('Invalid token or secret!');
    }
}
exports.verify = verify;
