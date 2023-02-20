"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.decrypt = exports.encrypt = void 0;
const sjcl_1 = __importDefault(require("sjcl"));
const defaults = { v: 1, iter: 10000, ks: 128, ts: 64, mode: "ccm", adata: "", cipher: "aes" };
function encrypt(secret, data, { expiresIn = 0 } = { expiresIn: 0 }) {
    const { ct, iv, salt } = JSON.parse(sjcl_1.default.encrypt(secret, JSON.stringify({ data, iat: Date.now(), exp: expiresIn })));
    return `${ct}.${iv}.${salt}`;
}
exports.encrypt = encrypt;
function decrypt(secret, token) {
    try {
        const [ct, iv, salt] = token.split('.');
        token = JSON.stringify(Object.assign({ ct, iv, salt }, defaults));
        const { data, iat, exp } = JSON.parse(sjcl_1.default.decrypt(secret, token));
        if (!exp || Date.now() < iat + exp)
            return data;
        throw new Error();
    }
    catch (_a) {
        throw new Error('Invalid token or secret!');
    }
}
exports.decrypt = decrypt;
