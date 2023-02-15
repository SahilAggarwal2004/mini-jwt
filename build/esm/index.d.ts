declare function sign(data: any, secret: string, expiresIn?: number): string;
declare function verify(token: string, secret: string): any;
export { sign, verify };
