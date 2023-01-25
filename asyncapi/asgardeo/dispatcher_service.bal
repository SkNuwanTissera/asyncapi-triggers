import ballerina/websub;
import ballerina/log;
import ballerina/http;
import ballerinax/asyncapi.native.handler;
import ballerina/jballerina.java as java;

service class DispatcherService {
    *websub:SubscriberService;
    private map<GenericServiceType> services = {};
    private handler:NativeHandler nativeHandler = new ();
    private string decryptionKey = "";
    private string keyAlgorithm = "";
    private string token = "";
    private string orgHandle = "";

    isolated function setOrgInfo(string key, string algo, string token, string organization) {
        self.decryptionKey = key;
        self.keyAlgorithm = algo;
        self.token = token;
        self.orgHandle = organization;
    }

    isolated function addServiceRef(string serviceType, GenericServiceType genericService) returns error? {
        if (self.services.hasKey(serviceType)) {
            return error("Service of type " + serviceType + " has already been attached");
        }
        self.services[serviceType] = genericService;
    }

    isolated function removeServiceRef(string serviceType) returns error? {
        if (!self.services.hasKey(serviceType)) {
            return error("Cannot detach the service of type " + serviceType + ". Service has not been attached to the listener before");
        }
        _ = self.services.remove(serviceType);
    }

    public function onEventNotification(websub:ContentDistributionMessage event) returns websub:Acknowledgement|error {
        EncryptedPayload payload = check event.content.cloneWithType();
        string decryptedEventMap = decrypt(java:fromString(payload.event), java:fromString(self.decryptionKey), java:fromString(self.keyAlgorithm));
        if decryptedEventMap is string {
            check self.emitEvent(payload, decryptedEventMap);
        }
        KeyData previousKey = check self.fetchPreviousDecryptionKey(self.token, self.orgHandle);
        string retryAttempt = decrypt(java:fromString(payload.event), java:fromString(previousKey.key), java:fromString("RSA"));
        if retryAttempt is string {
            check self.emitEvent(payload, retryAttempt);
        }
        return websub:ACKNOWLEDGEMENT;
    }

    function emitEvent(EncryptedPayload enPayload, string decryptedEventMap) returns error? {
        DecryptedPayload dePayload = {
            iss: enPayload.iss,
            jti: enPayload.jti,
            iat: enPayload.iat,
            aud: enPayload.aud,
            event: check decryptedEventMap.fromJsonString()
        };
        check self.matchRemoteFunc(dePayload.toJson());
    }

    isolated function fetchPreviousDecryptionKey(string token, string orgHandle) returns KeyData|error {
        http:Client httpClient = check new("localhost:9091/cryptokeyservice/");
        KeyData kd = check httpClient->get("crypto/"+orgHandle+"/keys/dec/1", {"Authorization":token});
        return kd;
    }

    public function onSubscriptionValidationDenied(websub:SubscriptionDeniedError msg) returns websub:Acknowledgement?|error {
        if (msg.message().includes("already registered")) {
            log:printInfo("Successfully subscribed to the event source");
        } else {
            log:printError("Subscription failed: " + msg.message());
        }
        return websub:ACKNOWLEDGEMENT;
    }

    public function onSubscriptionVerification(websub:SubscriptionVerification msg)
                        returns websub:SubscriptionVerificationSuccess|websub:SubscriptionVerificationError {
        log:printInfo("Successfully subscribed to the event source");
        return websub:SUBSCRIPTION_VERIFICATION_SUCCESS;
    }

    public function onUnsubscriptionVerification(websub:UnsubscriptionVerification msg)
                        returns websub:UnsubscriptionVerificationSuccess|websub:UnsubscriptionVerificationError {
        log:printInfo("Successfully unsubscribed from the event source");
        return websub:UNSUBSCRIPTION_VERIFICATION_SUCCESS;
    }

    private function matchRemoteFunc(json payload) returns error? {
        map<json> eventMap = <map<json>>(check payload.event);
        foreach string event in eventMap.keys() {
            GenericSecurityData securityData = check payload.cloneWithType(GenericSecurityData);
            match event {
                "urn:ietf:params:registrations:event:addUser" => {
                    AddUserData eventData = check eventMap.get(event).cloneWithType(AddUserData);
                    AddUserEvent addUserEvent = {securityData, eventData};
                    check self.executeRemoteFunc(addUserEvent, "urn:ietf:params:registrations:event:addUser", "RegistrationService", "onAddUser");
                }
                "urn:ietf:params:registrations:event:selfSignUpConfirm" => {
                    GenericUserData eventData = check eventMap.get(event).cloneWithType(GenericUserData);
                    GenericEvent genericEvent = {securityData, eventData};
                    check self.executeRemoteFunc(genericEvent, "urn:ietf:params:registrations:event:selfSignUpConfirm", "RegistrationService", "onSelfSignupConfirm");
                }
                "urn:ietf:params:registrations:event:askPasswordConfirm" => {
                    GenericUserData eventData = check eventMap.get(event).cloneWithType(GenericUserData);
                    GenericEvent genericEvent = {securityData, eventData};
                    check self.executeRemoteFunc(genericEvent, "urn:ietf:params:registrations:event:askPasswordConfirm", "RegistrationService", "onAskPasswordConfirm");
                }
                "urn:ietf:params:user-operations:event:lockUser" => {
                    GenericUserData eventData = check eventMap.get(event).cloneWithType(GenericUserData);
                    GenericEvent genericEvent = {securityData, eventData};
                    check self.executeRemoteFunc(genericEvent, "urn:ietf:params:user-operations:event:lockUser", "UserOperationService", "onLockUser");
                }
                "urn:ietf:params:user-operations:event:unlockUser" => {
                    GenericUserData eventData = check eventMap.get(event).cloneWithType(GenericUserData);
                    GenericEvent genericEvent = {securityData, eventData};
                    check self.executeRemoteFunc(genericEvent, "urn:ietf:params:user-operations:event:unlockUser", "UserOperationService", "onUnlockUser");
                }
                "urn:ietf:params:user-operations:event:updateUserCredentials" => {
                    GenericUserData eventData = check eventMap.get(event).cloneWithType(GenericUserData);
                    GenericEvent genericEvent = {securityData, eventData};
                    check self.executeRemoteFunc(genericEvent, "urn:ietf:params:user-operations:event:updateUserCredentials", "UserOperationService", "onUpdateUserCredentials");
                }
                "urn:ietf:params:user-operations:event:deleteUser" => {
                    GenericUserData eventData = check eventMap.get(event).cloneWithType(GenericUserData);
                    GenericEvent genericEvent = {securityData, eventData};
                    check self.executeRemoteFunc(genericEvent, "urn:ietf:params:user-operations:event:deleteUser", "UserOperationService", "onDeleteUser");
                }
                "urn:ietf:params:user-operations:event:updateUserGroup" => {
                    UserGroupUpdateData eventData = check eventMap.get(event).cloneWithType(UserGroupUpdateData);
                    UserGroupUpdateEvent userGroupUpdateEvent = {securityData, eventData};
                    check self.executeRemoteFunc(userGroupUpdateEvent, "urn:ietf:params:user-operations:event:updateUserGroup", "UserOperationService", "onUpdateUserGroup");
                }
                "urn:ietf:params:logins:event:loginSuccess" => {
                    LoginSuccessData eventData = check eventMap.get(event).cloneWithType(LoginSuccessData);
                    LoginSuccessEvent loginSuccessEvent = {securityData, eventData};
                    check self.executeRemoteFunc(loginSuccessEvent, "urn:ietf:params:logins:event:loginSuccess", "LoginService", "onLoginSuccess");
                }
            }
        }
    }

    private function executeRemoteFunc(GenericDataType genericEvent, string eventName, string serviceTypeStr, string eventFunction) returns error? {
        GenericServiceType? genericService = self.services[serviceTypeStr];
        if genericService is GenericServiceType {
            check self.nativeHandler.invokeRemoteFunction(genericEvent, eventName, eventFunction, genericService);
        }
    }
}

isolated function decrypt(handle encryptedText, handle decryptionKey, handle algo) returns string = @java:Method {
    'class: "io.crypto.Decryption",
    paramTypes: ["java.lang.String", "java.lang.String", "java.lang.String"]
} external;
