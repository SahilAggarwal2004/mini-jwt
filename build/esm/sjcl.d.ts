export default sjcl;
declare namespace sjcl {
    namespace misc {
        const _pbkdf2Cache: {};
        function cachedPbkdf2(password: string, obj?: Object | undefined): Object;
    }
}
