# credstore
BTP Credential Store Use Case Demo code

You will need to replace the default-services.json content with your key
And change the namespace, instance name, name of the object accordingly:
(async () => {
    xsenv.loadEnv();
    const binding = xsenv.getServices({ credstore: { name: 'CredentialStoreServiceInstance' } }).credstore[0].credentials;
    console.log(await readCredential(binding, "com.roy.cred", "password", "passTest"));
})();
