declare function sign(secret: string, data: any, { expiresIn, sl }?: {
    expiresIn: number;
    sl: number;
}): string;
declare function verify(secret: string, token: string): any;
declare function encrypt(secret: string, data: any, { expiresIn }?: {
    expiresIn: number;
}): string;
declare function decrypt(secret: string, token: string): any;
export { sign, verify, encrypt, decrypt };
