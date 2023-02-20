declare function encrypt(secret: string, data: any, { expiresIn }?: {
    expiresIn: number;
}): string;
declare function decrypt(secret: string, token: string): any;
export { encrypt, decrypt };
