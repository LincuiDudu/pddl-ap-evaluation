(define (domain attack-path-planner)
  (:requirements 
    :equality 
    :strips
    :typing
    :disjunctive-preconditions 
    :adl 
    :existential-preconditions
   )

  
  (:functions
    (total-cost) 
    (version ?Software) ;;（major*1e9 + minor*1e6 + patch*1e3 + milestone-seq*1）
    (port ?Port) ;; extract the opened port number
   )

  (:types

    attacker
    user
    application - software
    infrastructure 
     
    cve-identifier
    exploit-technique - technique


    mailer browser logback comchannel tomcat - software
    logback-config - file
    path
    directory - path
    message
    site
    controlled-server - server
    website 
    script
    env-var 
    url 
    file-url website-url script-url redirect-url locale-bypass-url - url 
    phishing-url - website-url
    java-library - library
    controller
    tls-connector - controller
    utility-class - class
    payload-string - string
    url-parser - parser
    social-media - platform
    information
    sensitive-information - information
    credential - sensitive-information
    internal-address - address
    endpoint
    account
    session-cookie  
    locale-config
    locale-bypass-parameter
    transformed-parameter
    data-binder
    disallowed-pattern
    parameter-name - string
    web-controller - controller
    spring-framework - framework
    spring-boot - software
    bouncy-castle
    bcjsse
    dns-server legitimate-server - server
    controlled-domain - dns-domain ;; "domain" is reserved keyword of pddl, can not define "domain" type
    ssl-certificate
    ip-address - address
    legitimate-ip-address malicious-ip-address - ip-address
    ssl-socket
    legitimate-service malicious-service - service
    receive-endpoint - endpoint
    api-endpoint soap-endpoint - receive-endpoint
    http-request - request
    http-post-request - http-request
    json-payload xml-payload - payload
    tcp-endpoint - endpoint
    tcp-server - server
    logback-receiver - receiver-component
    serialized-payload - payload
    tcp-connection - network-connection
    http2-server - tcp-server
    http2-library - library
    tls-endpoint - endpoint
    network-interface - interface
    tls-connection http2-connection - connection
    http2-settings-frame http2-settings-ack-frame rst-stream-frame - frame
    stream-limit
    stream-batch
    server-resource - resource
    spring-security - securit-module ;spring-product
    password - credential
    password-hash - password
    login-request 
    password-encoder -  encoder
    router-function
    resource-handler - handler 
    filesystem-resource - resource
    path-traversal-url - url
    path-traversal-payload - payload 
    sensitive-file - file
    filesystem-path - path
    snakeyaml-library - java-library
    yaml-endpoint - receive-endpoint
    command-execution-logic 
    rmi-service ldap-service - service
    jndi-endpoint - endpoint
    java-class - class
    java-gadget-class - java-class 
    yaml-payload - payload
    yaml-constructor - constructor
    default-servlet - servlet
    public-directory sensitive-directory - directory
    http-get-request http-put-request - http-request
    http-response 
    malicious-content - content
    content-range-headers
    file-extension
    web-shell-script - script
    jsp-engine - engine
    tomcat-process - process
    temporary-directory - directory
    host-os - operating-system
    filename-pattern - pattern
    sensitive-system-file - sensitive-file
    temporary-file - file
    symbolic-link - link
    controlled-file - file
    http-endpoint - endpoint
    etag-handler
    etag-value
    driver
    binary-stream-driver - driver
    binary-payload - payload
    pem-endpoint - receive-endpoint  
    pem-payload - payload
    asn1-structure - data-structure
    pem-file - file
    proxy
    reverse-proxy - proxy 
    trailer-header - request-header 
    session
    user-session - session
    cache-entry
    cache-poison-payload - payload    
    cached-resource - resource       
    application-cache        

   )


  (:constants

   CVE_2024_12798 - cve-identifier
   CVE_2024_38286 - cve-identifier
   CVE_2024_22243 - cve-identifier
   CVE_2024_38820 - cve-identifier
   CVE_2023_34055 - cve-identifier
   CVE_2024_34447 - cve-identifier
   CVE_2022_40150 - cve-identifier
   CVE_2022_40149 - cve-identifier
   CVE_2023_6378 - cve-identifier
   CVE_2023_44487 - cve-identifier
   CVE_2025_22228 - cve-identifier
   CVE_2024_38816 - cve-identifier
   CVE_2022_1471 - cve-identifier
   CVE_2025_24813 - cve-identifier
   CVE_2023_2976 - cve-identifier
   CVE_2024_22259 - cve-identifier
   CVE_2024_22262 - cve-identifier
   CVE_2024_38809 - cve-identifier
   CVE_2024_47072 - cve-identifier
   CVE_2023_33202 - cve-identifier
   CVE_2023_46589 - cve-identifier


   change-to-malicious-logback-config - exploit-technique
   abuse-tls-handshake - exploit-technique
   crafts-redirect-url - exploit-technique
   build-phishingsite - exploit-technique
   crafts-redirect-url-to-phishing-site - exploit-technique
   bypass-locale-specific-capitalization - exploit-technique
   acquire-user-account - exploit-technique
   craft-http-flood-script - exploit-technique
   perform-dns-poisoning - exploit-technique 
   sets-up-malicious-server - exploit-technique  
   craft-malicious-xml-payload - exploit-technique
   craft-malicious-json-payload - exploit-technique
   craft-malicious-serialized-payload - exploit-technique
   reset-http2-streams - exploit-technique
   online-brute-force - exploit-technique
   path-traversal - exploit-technique
   craft-malicious-java-class - exploit-technique
   yaml-deserialization - exploit-technique
   jndi-injection - exploit-technique
   internal-dot-path-manipulation - exploit-technique
   craft-partial-put-request - exploit-technique
   craft-malicious-web-shell - exploit-technique
   temp-file-prediction - exploit-technique
   temp-file-access - exploit-technique
   craft-malicious-etag-header - exploit-technique
   craft-malicious-binary-payload - exploit-technique
   craft-malicious-pem-payload - exploit-technique
   craft-malicious-pem-file - exploit-technique
   http-request-smuggling - exploit-technique
   
   
  )

  (:predicates

    ;; ============= attack goals ===============
    (spoofing ?Application - application)
    (tampering ?Application - application)
    (repudiation ?Application - application)
    (information-disclosure ?Application - application)
    (denial-of-service ?Application - application)
    (elevation-of-privilege ?Application - application)
   

    ;; ============ application exposes attack surface =================
    (exposed-attack-surface ?Application - application ?CVEID - cve-identifier)

    ;; ====================vulnerability exploit technique====================
    (exploit-by ?CVEID - cve-identifier ?exploitTechnique - exploit-technique)

    (exploit-needs-user-account ?CVEID - cve-identifier) 
    (vulnerable-spring-boot ?SpringBoot - spring-boot)
    (vulnerable-tomcat ?Tomcat - tomcat)
    (vulnerable-java-library ?Guava - java-library)
    (vulnerable-xstream-binary-driver ?XStreamLibrary - java-library)
    (vulnerable-bouncycastle ?Library - java-library)
    (vulnerable-host-validation ?Application - application)
    (vulnerable-pemparser-in-process ?Application - application)
    (vulnerable-redirect-URL-created ?MaliciousURL - redirect-url)
    (vulnerable-bcjsse ?Application - application ?BCJSSE - bcjsse)
    (vulnerable-dns-infrastructure ?DNSServer - dns-server)
    (vulnerable-jettison-parser ?JettisionLibrary - java-library)
    (vulnerable-logback-receiver ?ReceiverComponent - logback-receiver)
    (vulnerable-receiver ?ReceiverComponent - receiver-component)
    (vulnerable-http2-server ?Server - http2-server)
    (vulnerable-password-validation ?Application - application)
    (vulnerable-file-system-path-created ?ConcatenatedPath - filesystem-path)
    (vulnerable-tomcat-default-servlet ?Tomcat - tomcat ?DefaultServlet - default-servlet)
    (vulnerable-etag-parsing ?FW - spring-framework)

    ;; ============ Other states, relationships, non-numeric attributes of system configuration and external environment ============
    ; The application deploys logback
    (has-logback ?Application - application ?Logback - logback)  

    ;JaninoEventEvaluator enabled
    (janino-evaluator-enabled ?Application - application ?Logback - logback)

    ;Janino library 
    (has-library ?Application - application ?Library - java-library)
    (janino-library ?JaninoLib - java-library)
    

    ; Dynamic config loading enabled
    (dynamic-config-loading-enabled ?Application - application ?Software - software)

    ; User has write permission on configuration directory or env variables of some software
    (has-config-dir ?Software - software ?Directory - path)
    (has-access ?User - user ?Directory - path)
    (has-write-access ?User - user ?Directory - path)


    ; Janino code execution restrictions
    (has-code-execution-restriction ?Application - application ?Software - software)

    ; config integrity check
    (has-integrity-check ?Application - application ?Software - software ?ConfigFile - logback-config)
    (has-signature-verification ?Application - application ?Software - software ?ConfigFile - logback-config)

    ; Controllable env variables (allows specifying the configuration file path via environment variables.)
    (has-controllable-env-vars ?Application - application)

    (running-app ?Application - application)
    (malicious-config-loaded ?MaliciousFile - file )
    (malicious-config-loaded-via-config-dir ?MaliciousFile - file ?Directory - path)

    (script-execution-prompt-enabled ?Application - application)
    (com-channel-msg ?Comchannel - comchannel ?Message - message)
    (message-has-file ?Message - message ?File - file)
    (msg-opened ?Message - message)
    (running-communication-channel ?Comchannel - comchannel)
    (user-use-communication-channel ?User - user ?Comchannel - comchannel)
    (msg-reminder ?Message - message)
    (message-sent ?Message - message)
    (message-received ?Message - message)

    (has-janino-evaluator ?File - file)
    (contains-arbitrary-code ?File - file)
    (downloaded ?File - file)
    (in-directory ?User - user ?Directory - path)
    (located-at ?File - file ?Directory - path)
    (config-replaced ?File - file)
    
    (malicious-file ?MaliciousFile - file)
    (legitimate-file ?LegitimateFile - file) 
    (malicious-script ?MaliciousScript - script)
    (forged-website ?FoorgedWebsite - website)
    (malicious-url ?MaliciousUrl - url)
    (malicious-file-url ?MaliciousFileUrl - file-url)
    (malicious-website-url ?MaliciousWebUrl - website-url)
    (malicious-script-url ?MaliciousScriptUrl - script-url)
    (malicious-msg ?MaliciousMessage - message)
    (user-visits-site ?User - user ?Site - site)
    ;; Server hosting related
    (file-hosted-on-server ?File - file ?Server - server)               ; Malicious file hosted on server
    (url-points-to-file ?Url - url ?File - file)          ; Url points to a specific file
    (message-has-url ?Message - message ?Url - url)          ; Email message contains a url
    (url-accessed ?Url - url)              ; User has clicked the url
    (file-url-accessed ?FileUrl - file-url)
    (message-has-file-url ?Message - message ?FileUrl - file-url)

    ;; Predicates for Website-based Attack Vector
    (website-url-accessed ?WebsiteUrl - website-url) 
    (message-has-website-url ?Message - message ?WebsiteUrl - website-url) 
    (website-hosted-on-server ?Website - website ?Server - controlled-server)  
    (forged-website-contains-malicious-file-url ?ForgedWebsite - website ?MaliciousUrl - file-url) 
    (url-points-to-forged-website ?Url - url ?ForgedWebsite - website ) 
    (forged-website-visited-by-user ?ForgedWebsite - website ?User - user)  

    (env-var-logback-set-script  ?Script - script)
    (message-has-malicious-script ?MaliciousMessage - message ?MaliciousScript - script)
    (malicious-script-sets-env-var ?MaliciousScript - script ?EnvironmentVariable - env-var ?MaliciousFileUrl - file-url)
    (malicious-script-installed ?MaliciousScript - script)
    (env-var-set-by-malicious-url ?EnvironmentVariable - env-var ?FileUrl - file-url)
    (malicious-config-loaded-via-env-var ?MaliciousFile - file ?EnvVar - env-var)

    (malicious-script-execution-confirmed ?MaliciousScript - script)
    (malicious-script-execution-warning-active ?MaliciousScript - script)
    (malicious-script-downloaded ?MaliciousScript - script)
    (malicious-script-execution-activated ?MaliciousScript - script)

    (script-url-accessed ?MalScriptUrl - script-url)
    (url-points-to-script ?MalScriptUrl - script-url ?MaliciousScript - script)
    (malicious-script-hosted-on-server ?MaliciousScript - script ?ControlledServer - server)
    (message-has-malicious-script-url ?MaliciousMessage - message ?MalScriptUrl - script-url)

    (forged-website-contains-malicious-script-url ?ForgedWebsite - website ?MaliciousScriptUrl - script-url)
    (forged-website-contains-malicious-url ?ForgedWebsite - website ?MaliciousUrl - url)

    (has-tomcat ?Application - application ?Tomcat - tomcat)
    (tomcat-has-tls-connector ?Application - application ?Tomcat - tomcat ?TLSConnector - tls-connector)
    (tomcat-tls-renegotiation-enabled ?Application - application ?Tomcat - tomcat ?TLSConnector - tls-connector)
    (has-memory-limitation ?Application - application ?Tomcat - tomcat)
    (has-memory-protection-mechanisms ?Application - application)
    (max-connection-restriction ?Application - application)
    (firewall-connection-restriction ?Application - application)
    (IDS-monitoring ?Application - application)
    (IPS-monitoring ?Application - application)
    (WAF-monitoring ?Application - application)

    (tls-handshake-request-sent ?MaliciousRequestScript - script)
    (tls-handshake-request-received ?MaliciousRequestScript - script)

    (malicious-tls-flood-script ?MaliciousFloodScript - script)
    (tls-flood-script ?MaliciousFloodScript - script)
    (tomcat-tls-flood-script ?MaliciousFloodScript - script)
    (tls-flood-active ?MaliciousFloodScript - script)
    (much-memory-allocated ?Tomcat - software )
    (memory-exhausted ?Application)
    (resource-exhausted ?Application)
    (out-of-memory-error ?Application - application)

    (tls-initial-handshake-request-script ?MalTLSReScript - script)
    (malicious-initial-tls-handshake-script ?MalTLSReScript - script)

    (tls-renegotiation-script ?MalRenegoScript - script)
    (malicious-tls-renegotiation-script ?MalRenegoScript - script)
 
    
    (one-time-memory-allocated ?Tomcat - tomcat)
    (initial-tls-handshake-completed ?Tomcat - tomcat)

    (tls-renegotiation-flood-active ?MalRenegoScript - script)

    (has-dependency-on-vulnerable-paser ?Application - application ?Parser - url-parser)
    (has-external-settingable-endpoint ?Application - application ?Endpoint - endpoint)
    (url-redirect-enabled ?Application - application)
    (url-endpoint-setting-restriction ?Application - application ?Endpoint - endpoint)
     
    (external-resource-accessable ?Application - application)
    (internal-resource-accessable ?Application - application)
    
    (anti-redirect-protection ?Application - application)

    (WAF-malicious-request-bloack ?Application - application)
    (IPS-malicious-request-bloack ?Application - application)
 
    (website-mimics-legitimate-app ?PhishingSite - website ?Application - application)
    (phishing-url-points-to-forge-website ?PhishingURL - phishing-url ?PhishingSite - website )
    (malicious-redirect-url ?MaliciousRedirectURL - redirect-url)
    (HTTP-request-includes-redirect-url ?RedirectUrl - redirect-url)
    (malicious-phishing-site-url ?PhishingURL -  phishing-url)

    (URL-contains-payload ?MaliciousRedirectURL - redirect-url ?Payload - payload-string)
    (parsed-with ?Application - application ?Parsetool - url-parser)
    (running-Parser ?Parser - url-parser)
    (payload-has-validation-bypass-capability ?Payload - payload-string)
    (redirects-to-phishing-URL ?MaliciousRedirectURL - redirect-url  ?PhishingURL - phishing-url)
    (message-has-redirect-url ?Message - message ?MaliciousURL - redirect-url)            
    (redirect-url-clicked ?RedirectUrl - redirect-url) 
    (http-request-triggered ?Url - url)
    (http-request-sent ?HTTPRequest - http-request)
    (http-request-received ?HTTPRequest - http-request ?Application - application)
    (URL-host-validation-passed ?RedirectUrl - redirect-url)
    (redirect-response-sent ?PhishingUrl - phishing-url)
    (request-sent-to-phishing ?PhishingURL - phishing-url)
    (mimic-response-sent ?PhishingURL - phishing-url)
    (user-viewing-phishing-website ?User - user ?Phishingsite - website)
    (user-has-valid-credentials-application ?User - user ?Credentials - credential ?Application - application)
    (is-default-browser ?Browser - browser)
    (running-browser ?Browser - browser)
    (credentials-entered-to-phishingsite ?Credentials - credential ?PhishingSite - website)
    (credentials-submitted-on-phishingsite ?Credentials - credential ?PhishingSite - website)
    (information-obtained ?SensitiveInformation - sensitive-information)

    (redirect-url-published-on-social-media ?RedirectURL ?SocialMedia)
    (redirect-url-visible ?RedirectURL ?SocialMedia)
    (malicious-url-published-on-social-media ?MaliciousURL - url ?SocialMedia - social-media)
    (malicious-url-visible ?MaliciousURL - url ?SocialMedia - social-media)
    (running-social-media ?SocialMedia - social-media)
    (user-scrolling-social-media ?User - user ?SocialMedia - social-media)
    (user-use-browser ?User - user ?Browser - browser)
    (malicious-url-noticed ?MaliciousURL - url ?User - user)
    (malicious-url-clicked ?MaliciousURL - url)            
    (malicious-redirect-url-clicked ?MaliciousURL - redirect-url)
    (redirects-to-internal-resource ?MaliciousURL - redirect-url ?InternalResourceAddress -  internal-address)
    (internal-request-sent ?InternalResourceAddress -  internal-address)
    (sensitive-information-located-internal-address ?Data - sensitive-information ?InternalResourceAddress -  internal-address)
    (data-saved-in-internal-address ?Data - information ?InternalResourceAddress - internal-address)
    (data-sent-to-attacker ?Data - sensitive-information)

    (has-dependency-on-spring-framework ?Application - application ?SpringFramework - spring-framework)
      
    (has-vulnerable-databinder ?application - application ?databinder - data-binder)
    (databinder-parameter-binding-enabled ?Application - application ?DataBinder - data-binder)
    (has-disallowed-databinder-fields-configuration ?Application - application)
    (databinder-has-write-access-to-properties ?Application - application ?DataBinder - data-binder)
    (databinder-has-additional-input-validation-layer ?Application - application ?DataBinder - data-binder)      
    (databinder-relies-on-case-insensitive-field-matching ?Application - application ?DataBinder - data-binder)
    

    (has-locale-configuration ?Application - application ?config - locale-config)
    (has-locale-specific-exceptions ?Application - application)
    (has-vulnerable-locale-transformation ?Application - application)
    (processes-requests-in-locale-context ?Application - application)
    (locale-has-special-case-conversion ?Application - application)

    (locale-dependent-string-processing ?Application - application)
    (explicit-locale-specification-in-lowercase ?Application - application)

    (has-web-controller-accept-http-post-user-input ?Application - application ?Controller - web-controller)
    (accepts-user-controlled-parameter-names ?Application - application)

    (has-additional-field-access-controls ?Application - application)
    (has-parameter-name-sanitization ?Application - application)
    (has-WAF-case-manipulation-rules ?Application - application)
    (has-input-filter-case-bypass-detection ?Application - application)
     
    ;; === Account and Authentication Predicates ===
    (account-registered ?account - account ?application - application)
    (attacker-has-account ?account - account)
    (session-cookie-obtained ?cookie - session-cookie ?account - account)
    (account-has-normal-privileges ?account - account)
    (account-has-admin-privilege ?account - account)
    (admin-field-set-to-true ?account - account)

    ;; === Malicious URL and Parameter Predicates ===
    (malicious-locale-bypass-url ?url - locale-bypass-url)
    (url-contains-locale-bypass-parameter ?url - locale-bypass-url ?param - locale-bypass-parameter)
    (parameter-uses-non-standard-capitalization ?param - locale-bypass-parameter)
    (parameter-targets-admin-field ?param - locale-bypass-parameter)
    (bypass-parameter-created ?param - locale-bypass-parameter)

    ;; === HTTP Request Predicates ===
    (http-get-request-triggered ?url - url)
    (http-get-request-sent ?HttpGetRequest - http-get-request)
    (http-get-request-received ?HttpGetRequest - http-get-request ?Application - application)
    (request-contains-locale-bypass-param ?url - locale-bypass-url ?param - locale-bypass-parameter)
    (bypass-parameter-received ?param - locale-bypass-parameter ?application - application)

    ;; === DataBinder and Parameter Transformation Predicates ===
    (databinder-invoked ?databinder - data-binder ?param - locale-bypass-parameter)
    (parameter-transformed-to-lowercase ?original - locale-bypass-parameter ?transformed - transformed-parameter)
    (non-standard-lowercase-created ?param - transformed-parameter)
    (transformed-parameter-name ?param - transformed-parameter)

    ;; === Security Filter and Validation Predicates ===
    (pattern-matching-failed ?param - transformed-parameter ?pattern - disallowed-pattern)
    (filter-bypassed ?param - transformed-parameter)
    (parameter-allowed-to-continue-binding ?param - transformed-parameter)
    (validation-bypass-successful ?param - transformed-parameter)
  
    ;; === Exploitation Success Predicates ===
    (privilege-escalation ?account - account)
    (vulnerability-exploited ?cve - cve-identifier)
      
    (has-spring-boot ?Application - application ?SpringBoot - spring-boot)
    (spring-boot-has-mvc ?Application - application ?SpringBoot - spring-boot)
    (spring-boot-has-webflux ?Application - application ?SpringBoot - spring-boot)
    (has-actuator-dependency ?Application - application ?SpringBoot - spring-boot)
    (web-metrics-enabled ?Application - application ?SpringBoot - spring-boot)
    (accepts-external-http-requests ?Application - application)
    (actuator-endpoints-accessible ?Application - application)
    (web-observations-active ?Application - application ?SpringBoot - spring-boot)
    (request-size-limits ?Application - application)
    (resource-consumption-controls ?Application - application)
    (http-flood-script ?Script - script)
    (malicious-http-flood-script ?Script - script)
    (http-flood-active ?Script - script)
    (http-requests-sent ?Script - script)
    (http-requests-received ?Script - script)
    (resources-allocated ?SpringBoot - spring-boot)
    (resources-exhausted)

    ;; Application and Bouncy Castle related predicates
    (has-bouncy-castle ?Application - application ?BouncyCastle - bouncy-castle)
    (bcjsse-enabled ?Application - application ?BouncyCastle - bouncy-castle ?BCJSSE - bcjsse)
    (endpoint-identification-enabled ?Application - application ?BCJSSE - bcjsse)
    (ssl-socket-without-explicit-hostname ?Application - application)
    (https-connections-trigger-dns-resolution ?Application - application)
    (additional-certificate-validation ?Application - application)
    (dns-traffic-interception-allowed ?Application - application)

    ;; DNS Server related predicates
    (dnssec-enabled ?DNSServer - dns-server)
    (dns-predictable-source-ports ?DNSServer - dns-server)
    (outdated-dns-software ?DNSServer - dns-server)
    (dns-attacker-network-reach ?DNSServer - dns-server)
    (dns-doh-enabled ?DNSServer - dns-server)
    (dns-dot-enabled ?DNSServer - dns-server)
    (dns-insufficient-rate-limiting ?DNSServer - dns-server)
    (dns-predictable-transaction-ids ?DNSServer - dns-server)

    ;; Domain and Server related predicates
    (legitimate-server-ip-address ?Server - server ?Address -  legitimate-ip-address)
    (controlled-server-ip-address ?ControlledServer - controlled-server ?Address - malicious-ip-address)
    (malicious-server-setup-with-domain ?ControlledServer - controlled-server ?Domain - dns-domain)
    (malicious-server-ready ?ControlledServer - controlled-server)

    ;; SSL Certificate related predicate
    (valid-ssl-certificate ?Certificate - ssl-certificate ?Domain - dns-domain)
    (attacker-has-certificate ?Certificate - ssl-certificate)
    (server-configured-with-certificate ?ControlledServer - controlled-server ?Certificate - ssl-certificate)
    (ssl-certificate-presented ?ControlledServer - controlled-server ?Certificate - ssl-certificate)
    (certificate-verification-pending ?Certificate - ssl-certificate)
    (certificate-validation-passed-incorrectly ?Certificate - ssl-certificate)

    ;; DNS Poisoning related predicates
    (dns-poisoned ?DNSServer - dns-server ?LegitimateServer - legitimate-server ?MaliciousAddress - malicious-ip-address)
    (forged-dns-records ?DNSServer - dns-server ?LegitimateServer - legitimate-server ?MaliciousAddress - malicious-ip-address)
    (dns-lookup-performed ?Application - application ?Server - server)
    (dns-query-sent ?Application - application ?DNSServer - dns-server ?Server - server)
    (dns-response-returned ?DNSServer - dns-server ?Server - server ?Address - ip-address)
    (ip-address-resolved ?Server - server ?Address - ip-address)

    ;; User and Application interaction predicates
    (application-launched ?User - user ?Application - application)
    (user-session-active ?User - user ?Application - application)
    (connection-initiated ?User - user ?Application - application ?Server - server)
    (connection-request-pending ?Application - application ?Server - server)

    ;; SSL Socket related predicates
    (ssl-socket-created ?Application - application ?Socket - ssl-socket)
    (hostname-parameter-missing ?Socket - ssl-socket)
    (ssl-connection-established ?Application - application ?Server - server)
    (connection-request-to-attacker-server ?Application ?ControlledServer)
    (connected-to-attacker-server ?Application - application ?ControlledServer - controlled-server)


    ;; Hostname verification related predicates
    (hostname-verification-bypassed ?Application - application ?BCJSSE - bcjsse)
    (connection-trusted-incorrectly ?Application - application)

    ;; Sensitive data related predicates
    ; (credentials-data ?Data - sensitive-information)
    (sensitive-information-inputted ?User - user ?Data - sensitive-information)
    (data-ready-for-transmission ?Application - application ?Data - sensitive-information)
    (sensitive-information-transmitted ?Application - application ?Data - sensitive-information)
    (sensitive-data-sent-to-attacker ?Data - sensitive-information)
    (sensitive-information-captured ?Data - sensitive-information)

    ;; Service and impersonation related predicates
    (credential-reuse-attack ?Data - sensitive-information ?LegitimateService - legitimate-service)
    (user-impersonation ?User - user)

    (jettison-library ?JettisionLibrary - java-library)
    (has-api-endpoint ?Application - application ?APIEndpoint - api-endpoint)
    (has-soap-endpoint ?Application - application ?SOAPEndpoint - soap-endpoint)
    (has-receive-endpoint ?Application - application ?APIEndpoint - receive-endpoint)
    (accepts-json-input ?Application - application ?APIEndpoint - api-endpoint)
    (api-endpoint-has-input-validation ?Application - application ?APIEndpoint - api-endpoint)
    (api-endpoint-has-input-size-limits ?Application - application ?APIEndpoint - api-endpoint)
    (api-endpoint-has-complexity-limits ?Application - application ?APIEndpoint - api-endpoint)
    (api-endpoint-has-input-sanitization ?Application - application ?APIEndpoint - api-endpoint)
    (api-endpoint-has-preprocessing-detection ?Application - application ?APIEndpoint - api-endpoint)
    (has-heap-memory-consumption-limits ?Application - application )
    (has-heap-memory-monitoring ?Application - application)
    (has-memory-consumption-limits ?Application - application)
    (has-memory-monitoring ?Application - application)
    (has-heap-memory-isolation ?Application - application)
    (has-heap-memory-quotas ?Application - application)
    (has-throttling-mechanisms ?Application - application ?APIEndpoint - api-endpoint)
    (has-waf-protection ?Application - application)
    (has-waf-json-payload-detection ?Application - application)
  
    (json-payload ?MaliciousPayload - json-payload)
    (malicious-payload ?MaliciousPayload - payload)
    (deeply-nested-json ?MaliciousPayload - json-payload)
    (memory-exhaustion-payload ?MaliciousPayload - payload)
    (http-post-request-sent ?HTTPRequest - http-post-request)
    (malicious-payload-transmitted ?MaliciousPayload - payload) 
    (http-post-request-received ?Application - application ?HTTPRequest - http-post-request)
    (json-payload-extracted ?Application - application ?MaliciousPayload - json-payload)
    (jettison-parser-invoked ?JettisionLibrary - java-library ?MaliciousPayload - json-payload)
    (json-parsing-started ?JettisionLibrary - java-library)
    (heap-memory-allocated ?JettisionLibrary - java-library)
    (json-object-graph-construction ?JettisionLibrary - java-library)
    (excessive-heap-memory-consumption ?Application - application)
    (heap-memory-exhausted ?Application - application)
    (garbage-collection-capacity-exceeded ?Application - application)
    (application-unresponsive ?Application - application)

    (deeply-nested-xml ?XMLPayload - xml-payload )
    (xml-payload-extracted ?Application - application ?XMLPayload - xml-payload )
    (xml-to-json-transformation-started ?JettisionLibrary - java-library ?XMLPayload - xml-payload )
  
    (has-stack-memory-consumption-limits ?Application - application )
    (has-stack-memory-monitoring ?Application - application)
    (has-stack-memory-isolation ?Application - application)
    (has-stack-memory-quotas ?Application - application)
    (excessive-stack-memory-consumption ?Application - application)
    (stack-memory-allocated ?JettisionLibrary - java-library)
    (stack-memory-exhausted ?Application - application)

    (logback-library ?LogbackLibrary - java-library)
    (has-receiver-component ?Application - application ?ReceiverComponent - logback-receiver)
    (logback-receiver-deployed ?ReceiverComponent - logback-receiver)
    (logback-receiver-configured ?ReceiverComponent - logback-receiver)
    (logback-receiver-has-tcp-endpoint ?Application - application ?TCPEndpoint - tcp-endpoint)
    (logback-receiver-listens-on-port ?ReceiverComponent - logback-receiver ?TCPEndpoint - tcp-endpoint)
    (tcp-endpoint-external-access-allowed ?TCPEndpoint - tcp-endpoint)
    (tcp-endpoint-firewall-permits-inbound ?TCPEndpoint - tcp-endpoint)
    (has-deserialization-validation ?Application - application)
    (has-input-sanitization ?Application - application)
    (has-deserialization-filtering ?Application - application)
    (logback-receiver-requires-authentication ?ReceiverComponent - logback-receiver)
    (logback-receiver-accepts-remote-events ?ReceiverComponent - logback-receiver)
    (logback-receiver-configured-in-logback-xml ?ReceiverComponent - logback-receiver)
    (has-ips-protection ?Application - application)
    (has-serialized-payload-detection ?Application - application)
    (has-proper-exception-handling ?Application - application)
    (has-server ?Application - application ?Server - server)
    (has-tcp-server ?Application - application ?Server - tcp-server)
    (server-has-tcp-endpoint ?Server - server ?TCPEndpoint - tcp-endpoint)
    (server-listens-on-port ?Server - server)


    (deserialization-exploit-payload ?MaliciousPayload - serialized-payload)
    (tcp-connection-established ?Server - tcp-server ?TCPConnection - tcp-connection)
    (connected-to-receiver ?TCPConnection - tcp-connection ?ReceiverComponent - receiver-component)
    (payload-sent-through-tcp ?TCPConnection - tcp-connection ?MaliciousPayload - payload)
    (tcp-connection-received ?Application - application ?TCPConnection - tcp-connection)
    (plaintext-data-received ?Application - application ?MaliciousPayload - payload)
    (serialized-payload-extracted ?ReceiverComponent - receiver-component ?MaliciousPayload - serialized-payload)
    (deserialization-started ?ReceiverComponent - receiver-component ?MaliciousPayload - serialized-payload)
    (malicious-deserialization-triggered ?Application - application)
    (infinite-recursion-triggered ?Application - application)
    (stack-overflow-occurred ?Application - application)

    (has-http2-implementation ?Application - application ?Server - http2-server ?HTTP2Implementation - http2-library)
    (http2-stream-multiplexing-enabled ?Application - application ?Server - http2-server)
    (http2-server-has-network-interface ?Application - application ?Server  - http2-server ?HTTPInterface - network-interface)
    (http2-server-public-facing-interface ?Application - application ?HTTPInterface - network-interface)
    (http2-connections-accepted ?Application - application ?HTTPInterface - network-interface)
    (http2-server-processes-headers-frames ?Server - http2-server)
    (http2-server-processes-rst-stream-frame ?Server - http2-server)
    (http2-server-has-frame-rate-limiting ?Server - http2-server)
    (http2-server-allocates-stream-resources ?Application - application ?Server - http2-server)
    (http2-server-allocates-header-parsing-resources ?Application - application ?Server - http2-server)
    (http2-server-allocates-url-mapping-resources ?Application - application ?Server - http2-server)
    (http2-server-allows-immediate-rst-stream ?Application - application ?Server - http2-server)
    (http2-server-requires-stream-coordination ?Application - application ?Server - http2-server)
    (http2-server-enforces-canceled-request-limits ?Application - application ?Server - http2-server)
    (http2-server-canceled-requests-not-counted-toward-limits ?Application - application ?Server - http2-server)
    (http2-server-has-connection-level-pattern-tracking ?Application - application ?Server - http2-server)
    (http2-server-detects-rapid-creation-cancellation-patterns ?Application - application ?Server - http2-server)
    (http2-server-maintains-connections-after-cancellation ?Application - application ?Server - http2-server)
    (http2-server-allows-indefinite-stream-creation ?Application - application ?Server - http2-server)
    (http2-server-implements-goaway-frame-abuse-detection ?Application - application ?Server - http2-server)
    (http2-server-has-immediate-connection-termination ?Application - application ?Server - http2-server)
    (http2-server-vulnerable-http2-implementation ?HTTP2Implementation - http2-library)
    (http2-server-nodejs-implementation ?HTTP2Implementation - http2-library) 
    (http2-server-nghttp2-implementation ?HTTP2Implementation - http2-library) 
    (http2-server-netty-implementation ?HTTP2Implementation - http2-library) 
    (http2-server-envoy-implementation ?HTTP2Implementation - http2-library)
    (http2-server-eclipse-jetty-implementation ?HTTP2Implementation - http2-library)
    (http2-server-caddy-implementation ?HTTP2Implementation - http2-library) 
    (http2-server-has-rapid-reset-ddos-protection ?Application - application ?Server - http2-server)
    (http2-server-has-rapid-reset-pattern-detection ?Application - application ?Server - http2-server)

    (insufficient-resource-limits ?Application - application ?Server - server)
    (http2-server-can-handle-rapid-allocation-cancellation-cycles ?Application - application ?Server - http2-server)
    (three-way-handshake-completed ?TCPConnection - tcp-connection)
    (tls-connection-established ?TLSConnection - tls-connection ?Server - server)
    (secure-channel-created ?TLSConnection - tls-connection)
    (http2-settings-frame-sent ?SettingsFrame - http2-settings-frame)
    (http2-parameter-negotiation-initiated ?Server - http2-server)
    (http2-settings-frame-response-sent ?Server - http2-server)
    (http2-max-concurrent-streams-announced ?Server - http2-server ?MaxConcurrentStreams - stream-limit)
    (http2-settings-ack-frame-sent ?SettingsAckFrame - http2-settings-ack-frame)
    (http2-settings-ack-frame-received ?SettingsAckFrame - http2-settings-ack-frame)
    (http2-connection-ready ?Server - http2-server)
    
     
    (http2-connection-established ?HTTP2Connection - http2-connection ?Server - http2-server)
    (http2-server-ready-for-stream-creation ?Server - http2-server)
    (http2-server-rapid-reset-attack-possible ?Server - http2-server)
    (rapid-reset-attack-possible ?Server -server)

    (parallel-streams-initiated ?StreamBatch - stream-batch)
    (large-stream-batch-created ?StreamBatch - stream-batch)
    (rapid-stream-creation-started ?Server - http2-server)
    (stream-ids-allocated ?Server - http2-server  ?StreamBatch - stream-batch)
    (cpu-cycles-allocated ?ResourcePool - server-resource ?StreamBatch - stream-batch)
    (memory-buffers-allocated ?ResourcePool - server-resource ?StreamBatch - stream-batch)
    (connection-state-allocated ?ResourcePool - server-resource ?StreamBatch - stream-batch)
    (server-resource-consumed ?Server - server ?ResourcePool - server-resource)
    (rst-stream-frames-sent ?RstStreamFrames - rst-stream-frame?StreamBatch - stream-batch)
    (stream-cancellation-requests-sent ?Server - http2-server)
    (rst-stream-frames-received ?Server - http2-server ?RstStreamFrames - rst-stream-frame)
    (stream-cancellation-processing-triggered ?Server - http2-server)
    (rst-stream-processing-attempted ?Server - http2-server)
    (resource-deallocation-attempted ?Server - http2-server ?ResourcePool - server-resource)
    (processing-pace-insufficient ?Server - server)
    (cpu-cycles-exhausted ?ResourcePool - server-resource)
    (memory-buffers-exhausted ?ResourcePool - server-resource)
    (connection-state-exhausted ?ResourcePool - server-resource)
    (server-resource-exhausted ?Server - server)
    (vulnerable-spring-framework ?SpringFramework - spring-framework)
    
    (has-dependency-on-spring-security ?Application - application ?SpringSecurity - spring-security)
    (use-bcrypt-password-encoder ?Application - application ?PasswordEncoder - password-encoder)
    (allows-long-passwords ?Application - application)
    (password-length-validation ?Application - application)
    (multi-fator-auth-enabled ?Application - application)
    (two-factor-auth-enabled ?Application - application)
    (password-truncation-warning ?Application - application)
    (account-lockout-policy ?Application - application)
    (rate-limiting-enabled ?Application - application)
    (anomaly-detection-enabled ?Application - application)
    (pre-hashing-implemented ?Application - application)
    (sha256-pre-hash-enabled ?Application - application)
    (user-needs-to-use-application ?User - user ?Application - application)
    (user-password-set ?User -user ?Password - password)
    (password-longer-than-72-chars ?Password - password )
    (weak-first-72-chars ?Password - password)
    (user-has-long-weak-password ?User -user ?Password - password ?Application - application)
    (password-truncated-to-72-chars ?Password - password)
    (password-hash-created ?PasswordHash - password-hash ?Password - password)
    (password-hash-saved ?PasswordHash - password-hash ?Application - application)
    (request-contains-long-password ?LoginRequest - login-request ?InputPassword - password)
    (stored-hash-only-covers-first-72-chars ?PasswordHash - password-hash) 
    (online-brute-force-script ?Script - script)
    (script-targets-application ?Script - script ?Application - application)
    (automated-brute-force-capability ?Script - script)
    (script-generates-long-passwords ?Script - script)
    (large-volume-login-requests-sent ?LoginRequests - login-request ?Application - application)
    (requests-contain-long-password ?LoginRequests - login-request ?InputPassword - password)
    (brute-force-attack-initiated ?Application - application)
    (requests-bypass-detection ?LoginRequests - login-request ?Application - application)
    (login-request-received ?LoginRequest - login-request ?Application - application)
    (password-input-truncated ?InputPassword - password)
    (truncated-to-72-chars ?InputPassword - password)
    (bcrypt-processing-initiated ?InputPassword - password)
    (input-password-hashed ?InputPassword - password)
    (hash-ready-for-comparison ?InputPassword - password)
    (hash-comparison-performed ?InputPassword - password ?StoredHash - password-hash)
    (hashes-match ?InputPassword - password ?StoredHash - password-hash)
    (authentication-successful ?Application - application)
    (unauthorized-access-granted ?Application - application)

  (uses-WebMvc-web-framework ?Application - application)
  (uses-WebFlux-web-framework ?Application - application)
  (has-router-function-configured ?Application - application ?RouterFunction - router-function)
  (router-function-serves-static-resources ?RouterFunction - router-function)
  (has-filesystem-resource-configured ?Application - application ?FileSystemResource - filesystem-resource)
  (points-to-filesystem-path ?FileSystemResource - filesystem-resource)
  (has-filesystem-read-access ?Application - application)
  (sensitive-files-accessible ?Application - application)
  (spring-security-http-firewall-enabled ?Application - application)
  (runs-on-tomcat ?Application - application)
  (runs-on-jetty ?Application - application)
  (url-path-validation-enabled ?Application - application)
  (has-WAF-path-traversal-protection ?Application - application)
  (filesystem-permissions-allow-traversal ?Application - application)
  (malicious-path-traversal-url ?MaliciousURL - path-traversal-url)
  (URL-contains-path-traversal-payload ?MaliciousURL - path-traversal-url ?Payload - path-traversal-payload)
  (request-contains-path-traversal-payload ?Payload)
  (plaintext-payload ?Payload - payload)  
  (encoded-payload ?Payload - payload)
  (decoded-payload ?Payload - payload)
  (payload-targets-sensitive-file ?Payload - path-traversal-payload ?SensitiveFile - sensitive-file)
  (path-traversal-url-created ?MaliciousURL - path-traversal-url)
  (path-traversal-url-clicked ?MaliciousURL - path-traversal-url )
  (request-matched-to-handler ?TraversalUrl - path-traversal-url ?ResourceHandler - resource-handler)
  (request-routed-to-handler ?TraversalUrl - path-traversal-url ?ResourceHandler - resource-handler)
  (path-concatenated-without-normalization ?ConcatenatedPath - filesystem-path)
  (traversal-payload-in-path ?ConcatenatedPath - filesystem-path ?Payload - path-traversal-payload)
  (sensitive-data-read-from-filesystem ?Data - sensitive-information ?ConcatenatedPath - filesystem-path)
  (sensitive-data-prepared-by-application ?Application - application ?Data - sensitive-information)
  (data-stored-in-file ?Data - information ?SensitiveFile - file )

  (has-dependency-on-snakeyaml ?Application - application ?SnakeYAML - java-library)
  (implementated-by-java ?Application ?Java)
  (has-external-yaml-endpoint ?Application - application ?Endpoint -yaml-endpoint )
  (accepts-untrusted-yaml-input ?Application - application)
  (has-yaml-input-validation ?Application - application)
  (uses-default-constructor ?Application - application)
  (uses-safe-constructor ?Application - application)
  (has-yaml-type-restrictions ?Application - application)
  (has-sufficient-code-execution-privilege ?Application - application)
  (has-dangerous-class-instantiation-prevention ?Application - application)
  (has-sandbox-restrictions ?Application - application)
  (network-connectivity-available ?Application - application)
  (malicious-java-class ?MaliciousClass - java-class)
  (java-class-contains-command-execution-logic ?MaliciousClass - java-class ?CommandLogic - command-execution-logic)
  (class-hosted-on-server ?MaliciousClass - java-class ?AttackerServer - controlled-server)
  (malicious-class-accessible ?MaliciousClass - java-class )
  (malicious-ldap-service ?LDAPService - ldap-service)
  (malicious-rmi-service ?RMIService - rmi-service)
  (ldap-service-running ?LDAPService - ldap-service ?AttackerServer - controlled-server)
  (rmi-service-running ?RMIService - rmi-service ?AttackerServer - controlled-server)
  (malicious-jndi-endpoint ?Endpoint - jndi-endpoint)
  (endpoint-to-malicious-class ?Endpoint - jndi-endpoint  ?MaliciousClass - class)
  (jndi-endpoint-created ?Endpoint - jndi-endpoint)
  (malicious-yaml-payload ?YAMLPayload - yaml-payload )
  (payload-contains-java-gadget-chains ?YAMLPayload - yaml-payload ?GadgetClass - java-gadget-class)
  (references-jndi-endpoint ?YAMLPayload - yaml-payload ?JNDIEndpoint - jndi-endpoint)
  (yaml-payload-crafted ?YAMLPayload - yaml-payload)
  (malicious-yaml-transmitted ?YAMLPayload - yaml-payload)
  (request-includes-yaml-payload ?HTTPRequest - http-post-request ?YAMLPayload)
  (yaml-passed-to-loader ?YAMLPayload - yaml-payload ?SnakeYAML - snakeyaml-library)
  (yaml-deserialization-started ?YAMLPayload - yaml-payload ?Constructor - yaml-constructor)
  (running-constructor ?Constructor - constructor)
  (dangerous-gadget-class-instantiated ?GadgetClass - java-gadget-class )
  (gadget-class-active ?GadgetClass - java-gadget-class)
  (malicious-class-loaded ?MaliciousClass -  class)
  (jndi-lookup-executed ?JNDIEndpoint - jndi-endpoint)
  (malicious-class-instantiated ?MaliciousClass - class)
  (attacker-class-active ?MaliciousClass - class)
  (attacker-commands-executed ?CommandLogic - command-execution-logic)

  (tomcat-has-default-servlet ?Application - application ?DefaultServlet - default-servlet)
  (tomcat-default-servlet-write-enabled ?Application - application ?DefaultServlet - default-servlet)
  (partial-put-request-enabled ?Application - application)      
  (has-public-directory ?Application - application ?PublicDir - public-directory)
  (public-directory-exposed ?Application - application ?PublicDir - public-directory)
  (public-directory-has-sensitive-subdirectory ?PublicDir - public-directory ?SensitiveDir - sensitive-directory)
      
  (sensitive-filename-exposed ?Application - application ?SensitiveFile - sensitive-file)
  (sensitive-file-partial-put-uploaded-enabled ?Application - application ?SensitiveFile - sensitive-file)
        
  (tomcat-file-based-session-persistence-enabled ?Application - application ?Tomcat - tomcat) 
  (tomcat-default-session-storage-location ?Application - application ?Tomcat - tomcat)

  (http-put-method-accessible ?Application - application)
  (WAF-malicious-request-block ?Application - application)
  (security-controls-path-manipulation ?Application - application)

  (has-proper-path-normalization-for-filename ?Application - application)
  (has-proper-path-equivalence-validation-for-filename ?Application - application)

  (malicious-http-get-request ?HTTPGETRequest - http-get-request)
  (request-includes-internal-dot-path-manipulation ?HTTPGETRequest - http-request)
  (request-targets-sensitive-file ?HTTPRequest - http-request ?SensitiveFile - sensitive-file)

  (malicious-request-sent-to-tomcat ?HTTPGETRequest - http-get-request ?Tomcat - tomcat)
  (default-servlet-processing-request ?DefaultServlet - default-servlet ?HTTPRequest - http-request)
  (path-parsing-without-validation ?HTTPRequest - http-request)
  (internal-dot-section-ignored ?HTTPRequest - http-request)
  (path-incorrectly-normalized ?HTTPRequest - http-request)
  (access-restrictions-bypassed ?HTTPRequest - http-request)
  (sensitive-file-located ?SensitiveFile - sensitive-file)
  (sensitive-file-accessed ?SensitiveFile - sensitive-file)
  (file-content-retrieved ?Data - sensitive-information ?SensitiveFile - sensitive-file)
  (http-response-contains-sensitive-data ?HTTPGETRequest ?SensitiveData - sensitive-information)

  (malicious-content-created ?MaliciousContent - malicious-content)
  (content-targets-sensitive-file ?MaliciousContent -  malicious-content ?SensitiveFile - sensitive-file)
  (malicious-http-put-request ?HTTPPUTRequest - http-put-request)
  (put-request-targets-sensitive-file ?HTTPPUTRequest - http-put-request ?SensitiveFile - sensitive-file)
  (put-request-contains-malicious-content ?HTTPPUTRequest - http-put-request ?MaliciousContent - malicious-content)
  (partial-put-headers-configured ?ContentRangeHeaders - content-range-headers)
  (put-request-includes-malicious-content ?HTTPPUTRequest - http-put-request)
  (http-put-request-sent ?HTTPPUTRequest - http-put-request)
  (http-put-request-received ?HTTPPUTRequest - http-put-request ?Application - application)
  (malicious-content-written-to-file ?MaliciousContent - malicious-content ?SensitiveFile - sensitive-file)
  (sensitive-file-tampered ?SensitiveFile - sensitive-file)

  (malicious-web-shell-script ?WebShellScript - web-shell-script)
  (web-shell-script-has-command-execution-capability ?WebShellScript - web-shell-script)
  (jsp-extension ?FileExtension - file-extension) 
  (jspx-extension ?FileExtension - file-extension)
  (web-shell-script-has-execution-extension ?WebShellScript - web-shell-script ?FileExtension - file-extension)
  (server-side-executable ?WebShellScript - web-shell-script)
  (put-request-contains-web-shell-script ?HTTPPUTRequest - http-put-request ?WebShellScript - web-shell-script)
  (put-request-targets-web-directory ?HTTPPUTRequest - http-put-request  ?SensitiveDir - sensitive-directory)
  (web-directory-located ?SensitiveDir - sensitive-directory)
  (web-directory-accessed ?SensitiveDir - sensitive-directory)
  (web-shell-script-written-to-directory ?WebShellScript - web-shell-script ?SensitiveDir - sensitive-directory)
  (web-shell-script-uploaded-successfully ?WebShellScript - web-shell-script )
  (web-shell-script-accessible-via-http ?WebShellScript - web-shell-script)
  (request-includes-web-shell-script ?HTTPGETRequest - http-request)
  (web-shell-script-access-request-received ?Application - application ?WebShellScript - web-shell-script)
  (get-request-targets-web-shell-script ?HTTPGETRequest - http-get-request ?WebShellScript - web-shell-script)
  (tomcat-has-jsp-engine ?Tomcat - tomcat ?JSPEngine - jsp-engine)
  (tomcat-jsp-engine-enabled ?Application - application ?Tomcat - tomcat )
  (jsp-engine-processing-web-shell-script ?JSPEngine - jsp-engine ?WebShellScript - web-shell-script)
  (web-shell-script-parsed ?WebShellScript - web-shell-script)
  (has-tomcat-process ?Application - application ?TomcatProcess - tomcat-process)
  (web-shell-script-executed-with-privileges ?WebShellScript - web-shell-script  ?TomcatProcess - tomcat-process)
  (command-execution-capability-available ?WebShellScript - web-shell-script )
  (web-shell-interface-active ?WebShellScript - web-shell-script)
  (arbitrary-command-execution ?WebShellScript - web-shell-script)
  (system-commands-executed ?TomcatProcess - tomcat-process)

  (guava-library ?Guava - java-library)
  (uses-filebackedoutputstream ?Application - application)
  (uses-uncontrolled-createtempfile ?Application - application)
  (java-tmpdir-set-to-world-writable ?Application - application)
  (has-os ?Application - application  ?Host - host-os)
  (world-readable-tempdir-permissions ?Host - host-os)
  (world-writable-tempdir-permissions ?Host - host-os)
  (container-isolated ?Application - application)
  (os-sandbox-isolated ?Application - application)
  (uses-per-user-temp-directory ?Application - application)
  (temp-directory-acl-protected ?Application - application)
  (temp-directory-mount-restricted ?Application - application)
  (uses-predictable-temp-filenames ?Application - application)
  (writes-sensitive-data-to-temp ?Application - application)
  (temp-directory-under-surveillance ?TempDir - temporary-directory)

  (temp-directory-identified ?TempDir - temporary-directory)
  (attacker-knows-temp-location ?TempDir - temporary-directory)
  (filename-pattern-predicted ?NamingPattern - filename-pattern)
  (attacker-knows-naming-pattern ?NamingPattern - filename-pattern)
  (symbolic-link-created ?SymLink - symbolic-link)
  (symlink-placed-in-temp-dir ?SymLink - symbolic-link ?TempDir - temporary-directory)
  (symlink-uses-predicted-name ?SymLink - symbolic-link ?PredictedName - filename-pattern)
  (malicious-symlink-prepared ?SymLink - symbolic-link)
  (filebackedoutputstream-triggered ?Application - application)
  (temp-file-creation-requested ?Application - application)
  (temp-file-created ?TempFile - temporary-file)
  (temp-file-resolves-to-symlink ?TempFile - temporary-file ?SymLink - symbolic-link)
  (file-creation-exploited ?TempFile - temporary-file)
  (data-written-to-temp-file ?Data - sensitive-information ?TempFile - temporary-file)
  (sensitive-system-file-overwritten ?SensitiveFile - sensitive-system-file ?Data - sensitive-information)
  (unauthorized-file-modification ?SensitiveFile - sensitive-system-file)
  (tampering-achieved ?SensitiveFile - sensitive-system-file)
  (data-tampering ?Data - sensitive-information)
  (system-integrity-compromised ?SensitiveFile - sensitive-system-file)
  (symlink-points-to-file ?SymLink - symbolic-link ?File - file)
  (temp-file-actually-points-to ?TempFile ?File - file)
  (sensitive-data-written-to-attacker-controlled-file ?Data - sensitive-information ?AttackerControlledFile - controlled-file)
  (sensitive-data-buffering-initiated ?Application - application)
  (temp-file-in-directory ?TempFile - temporary-file  ?Dir - directory)
  (temp-file-has-insecure-permissions ?TempFile - temporary-file)
  (temp-file-world-readable ?TempFile - temporary-file)
  (file-ready-for-data-write ?File - file)
  (temp-file-contains-sensitive-data ?TempFile - temporary-file  ?SensitiveData - sensitive-information)
  (sensitive-data-exposed-in-filesystem ?SensitiveData - sensitive-information)
  (temp-file-populated-with-data ?TempFile - temporary-file)
  (temp-file-detected ?TempFile - temporary-file)
  (attacker-knows-temp-file-location ?TempFile - temporary-file)
  (file-accessible-for-reading ?TempFile - temporary-file)
  (temp-file-identified-by-pattern ?TempFile - temporary-file ?FilePattern - filename-pattern)
  (sensitive-data-accessed-by-attacker ?SensitiveData - sensitive-information)
  (data-confidentiality-breached ?SensitiveData - sensitive-information)
  (unauthorized-data-access ?SensitiveData - sensitive-information)

  ;; Framework / Version
  (has-framework ?App - application ?FW - spring-framework)
  (spring-web-module ?FW - spring-framework)

  ;; HTTP endpoint / ETag
  (has-http-endpoint ?App - application ?Endpoint - http-endpoint)
  (has-etag-handler ?App - application ?Handler - etag-handler)
  (processes-if-match-headers ?App - application ?Handler - etag-handler)
  (processes-if-none-match-headers ?App - application ?Handler - etag-handler)
  (has-etag-validation ?App - application ?Handler - etag-handler)
  (has-etag-size-limits ?App - application ?Handler - etag-handler)
  (has-etag-complexity-limits ?App - application ?Handler - etag-handler)

  ;; Access control / public exposure
  (publicly-accessible ?Endpoint - endpoint)
  (has-restrictive-access-controls ?Endpoint - http-endpoint)
  (has-header-size-limits ?App - application ?Endpoint - http-endpoint)
  (has-framework-header-limits ?FW - spring-framework)
  (has-servlet-container-limits ?App - application)
  (has-rate-limiting ?App - application ?Endpoint - api-endpoint)
  (has-request-throttling ?App - application ?Endpoint - http-endpoint)
  (has-input-validation-filters ?App - application)
  (has-etag-validation-middleware ?App - application)
  (has-etag-header-detection-rules ?App - application)

  ;; Shared resources / isolation
  (has-shared-resources ?App - application)
  (has-resource-isolation ?App - application)
  (has-shared-thread-pool ?App - application)
  (has-endpoint-isolation ?App - application)

  ;; Malicious request / ETag
  (malicious-http-request ?Request - http-request)
  (pathological-etag-value ?ETag - etag-value)
  (extremely-long-etag ?ETag - etag-value)
  (has-if-match-header ?Request - http-request ?ETag - etag-value)
  (malicious-etag-transmitted ?MaliciousETag - etag-value)

  ;; TCP connection
  (tcp-connection-initiated ?Conn - tcp-connection ?Endpoint - http-endpoint)
  (http-request-bytes-read ?App - application ?Request - http-request)
  (request-parsing-initiated ?App - application)
  (if-match-header-extracted ?App - application ?ETag - etag-value)
  (etag-value-ready-for-parsing ?ETag - etag-value)

  ;; Spring parsing
  (spring-etag-parser-invoked ?FW - spring-framework ?ETag - etag-value)
  (etag-parsing-started ?FW - spring-framework)

  (excessive-cpu-consumption ?App - application)
  (excessive-memory-consumption ?App - application)
  (has-http-rate-limiting ?Application - application ?HTTPEndpoint - http-endpoint)

  ; Application / Library / Driver relationships
  (xstream-library ?XStreamLibrary - java-library)
  (has-binary-stream-driver ?Application - application ?BinaryDriver - binary-stream-driver)
  (binary-stream-driver ?BinaryDriver - binary-stream-driver)
  (xstream-uses-driver ?XStreamLibrary - java-library ?BinaryDriver - binary-stream-driver)

  ; API / Input relationships
  (accepts-binary-input ?Application - application ?APIEndpoint - api-endpoint)
  (processes-untrusted-input ?Application - application ?APIEndpoint - api-endpoint)
  (api-endpoint-has-integrity-checks ?Application - application ?APIEndpoint - api-endpoint)

  ; Security / Stack / Memory
  (has-stackoverflow-exception-handling ?Application - application)
  (has-defense-in-depth-safeguards ?Application - application)
  (has-recursive-structure-limits ?Application - application)
  (has-jvm-stack-size-restrictions ?Application - application)
  (has-sufficient-stack-limits ?Application - application)
  (has-input-stream-size-limits ?Application - application)
  (has-structural-complexity-limits ?Application - application)
  (has-sandboxing ?Application - application)
  (has-deserialization-whitelist ?Application - application)
  (has-waf-binary-filtering ?Application - application)

  ; Payload
  (binary-xstream-payload ?MaliciousPayload - binary-payload)
  (deeply-nested-binary ?MaliciousPayload - binary-payload)
  (recursive-mapping-payload ?MaliciousPayload - binary-payload)
  (stack-exhaustion-payload ?MaliciousPayload - binary-payload)
  (binary-payload-extracted ?Application - application ?MaliciousPayload - binary-payload)

  ; XStream execution
  (xstream-binary-driver-invoked ?XStreamLibrary - java-library ?MaliciousPayload - binary-payload)
  (binary-parsing-started ?XStreamLibrary - java-library)
  (call-stack-frames-allocated ?XStreamLibrary - java-library)
  (recursive-object-graph-construction ?XStreamLibrary - java-library)
  (recursive-mapping-token-resolution ?XStreamLibrary - java-library)

  (bouncycastle-library ?Library - java-library)
  (uses-pemparser ?Application - application)
  (has-pem-endpoint ?Application - application ?Endpoint - pem-endpoint)
  (accepts-pem-input ?Application - application ?Endpoint - pem-endpoint)
  (parser-in-process ?Application - application)
  (parser-shares-jvm-heap ?Application - application)

  (endpoint-has-content-type-enforcement ?Application - application ?Endpoint - pem-endpoint)
  (endpoint-has-asn1-sanity-checks ?Application - application ?Endpoint - pem-endpoint)
  (endpoint-rejects-suspicious-pem-patterns ?Application - application ?Endpoint - pem-endpoint)

  (endpoint-has-file-size-limits ?Application - application ?Endpoint - pem-endpoint)
  (endpoint-has-asn1-depth-limits ?Application - application ?Endpoint - pem-endpoint)
  (endpoint-has-parser-timeouts ?Application - application ?Endpoint - pem-endpoint)
  (endpoint-has-per-request-memory-caps ?Application - application ?Endpoint - pem-endpoint)

  (endpoint-reachable-to-attackers ?Application - application ?Endpoint - pem-endpoint)
  (endpoint-rate-limited ?Application - application ?Endpoint - pem-endpoint)

  (has-cgroup-memory-limit ?Application - application)
  (has-pod-memory-limit ?Application - application)
  (single-jvm-hosting-critical-services ?Application - application)
  (parsing-sandboxed ?Application - application)

  (has-circuit-breaker-for-oom ?Application - application)
  (graceful-degradation-on-oom ?Application - application)
  (has-upload-policy-scanner ?Application - application ?Endpoint - pem-endpoint)

  (malicious-pem-payload ?Payload - pem-payload)
  (payload-contains-asn1 ?Payload - pem-payload ?Asn1 - asn1-structure)
  (asn1-deeply-nested ?Asn1 - asn1-structure)
  (asn1-large-lengths ?Asn1 - asn1-structure)

  (http-request-targets-endpoint ?Request - http-post-request ?Endpoint - endpoint)
  
  (pem-payload-extracted ?Application - application ?Payload - pem-payload)
  (pemparser-invoked ?Library - java-library ?Payload - pem-payload)
  (pemparsing-started ?Library - java-library)

  (heap-memory-allocated-for-asn1 ?Library - java-library)
  (asn1-object-graph-construction ?Library - java-library)

  (pem-file ?File - file)
  (file-contains-asn1 ?File - file ?Asn1 - asn1-structure)
  (file-uploaded-to-application ?File - file ?Application - application)
  (file-targets-endpoint ?File - file ?Endpoint - pem-endpoint)
  (pem-file-received ?Application - application ?File - file)
  (payload-from-file ?Payload - pem-payload ?File - file)
  (has-account ?User - user ?Application - application)
  (malicious-file-transmitted ?MaliciousFile - file)
  (memory-exhaustion-file ?MaliciousPEMFile - file)
  
  (has-reverse-proxy ?Application - application ?ReverseProxy - reverse-proxy)
  (forwards-requests ?ReverseProxy - reverse-proxy ?Tomcat - tomcat)
  (has-endpoint ?Application - application ?Endpoint - endpoint)
  (accepts-chunked-encoding ?Application - application)
  (permits-trailer-headers ?ReverseProxy - reverse-proxy)
  (chunked-encoding-request ?HttpRequest - http-request)
    
  (mismatched-parsing ?ReverseProxy - reverse-proxy ?Tomcat - tomcat)
  (mismatched-trailer-handling ?ReverseProxy - reverse-proxy ?Tomcat - tomcat)
  (mismatched-header-limits ?ReverseProxy - reverse-proxy ?Tomcat - tomcat)
  (normalizes-trailer-headers ?ReverseProxy - reverse-proxy)
  (rejects-oversized-trailers ?ReverseProxy - reverse-proxy)
  (truncates-oversized-trailers ?ReverseProxy - reverse-proxy)
  (rejects-malformed-trailers ?ReverseProxy - reverse-proxy)
    
  (allows-connection-reuse ?ReverseProxy - reverse-proxy ?Tomcat - tomcat)
  (allows-keep-alive ?ReverseProxy - reverse-proxy ?Tomcat - tomcat)
  (allows-pipelining ?ReverseProxy - reverse-proxy ?Tomcat - tomcat)
  (user-tcp-connection-established ?TcpConnection - tcp-connection)
  (connection-reused ?TcpConnection - tcp-connection)
    
  (strict-per-request-auth ?Endpoint - endpoint)
  (authenticated-user-request ?HttpRequest - http-request)
    
    (has-waf-smuggling-detection ?Application - application)
    (has-ips-oversized-trailer-rules ?Application - application)
    (has-request-canonicalization ?Application - application)
    
    (frontend-connection-opened ?Attacker - attacker ?ReverseProxy - reverse-proxy ?TcpConnection - tcp-connection)
    (frontend-connection-accepted ?ReverseProxy - reverse-proxy ?TcpConnection - tcp-connection)
    (backend-connection-opened ?ReverseProxy - reverse-proxy ?Tomcat - tomcat ?TcpConnection - tcp-connection)
    (backend-connection-accepted ?Tomcat - tomcat ?TcpConnection - tcp-connection)
    (user-frontend-connection-opened ?User - user ?ReverseProxy - reverse-proxy ?TcpConnection - tcp-connection)
    (user-frontend-connection-accepted ?ReverseProxy - reverse-proxy ?TcpConnection - tcp-connection)
    
    (attacker-connected-to-proxy ?Attacker - attacker ?ReverseProxy - reverse-proxy)
    (proxy-connected-to-tomcat ?ReverseProxy - reverse-proxy ?Tomcat - tomcat)
    (user-connected-to-proxy ?User - user ?ReverseProxy - reverse-proxy)
    
    ; Request creation and payload predicates
    (trigger-request-sent ?Attacker - attacker ?HttpRequest - http-request)
    (oversized-trailer-header ?TrailerHeader - trailer-header)
    (desync-payload ?HttpRequest - http-request)
    (smuggled-request-sent ?Attacker - attacker ?HttpRequest - http-request)
    (session-hijack-payload ?HttpRequest - http-request)
    (privilege-escalation-payload ?HttpRequest - http-request)
    (user-request-sent ?User - user ?HttpRequest - http-request)
    
    (partial-request-received ?ReverseProxy - reverse-proxy ?HttpRequest - http-request)
    (request-in-proxy-buffer ?HttpRequest - http-request)
    (partial-request-parsed ?ReverseProxy - reverse-proxy ?HttpRequest - http-request)
    (partial-request-forwarded ?ReverseProxy - reverse-proxy ?HttpRequest - http-request)
    (smuggled-request-received-by-proxy ?ReverseProxy - reverse-proxy ?HttpRequest - http-request)
    (smuggled-payload-in-proxy-buffer ?HttpRequest - http-request)
    (smuggled-request-forwarded-to-tomcat ?ReverseProxy - reverse-proxy ?HttpRequest - http-request)
    (user-request-received-by-proxy ?ReverseProxy - reverse-proxy ?HttpRequest - http-request)
    (user-request-in-proxy-buffer ?HttpRequest - http-request)
    (user-request-forwarded-to-tomcat ?ReverseProxy - reverse-proxy ?HttpRequest - http-request)
    
    (request-in-transit-to-tomcat ?HttpRequest - http-request)
    (trigger-request-received ?Tomcat - tomcat ?HttpRequest - http-request)
    (complete-request-interpreted ?Tomcat - tomcat ?HttpRequest - http-request)
    (smuggled-request-in-transit-to-tomcat ?HttpRequest - http-request)
    (smuggled-request-received-by-tomcat ?Tomcat - tomcat ?HttpRequest - http-request)
    (smuggled-payload-queued ?Tomcat - tomcat ?HttpRequest - http-request)
    (user-request-in-transit-to-tomcat ?HttpRequest - http-request)
    (user-request-received-by-tomcat ?Tomcat - tomcat ?HttpRequest - http-request)
    (user-request-queued-for-processing ?HttpRequest - http-request)
    
    (desync-condition-created ?Tomcat - tomcat)
    (requests-interpreted-separately ?Tomcat - tomcat ?HttpRequest1 - http-request ?HttpRequest2 - http-request)
    (smuggled-request-ready-for-processing ?HttpRequest - http-request)
    (request-boundary-confusion ?Tomcat - tomcat)
    
    (response-sent ?Tomcat - tomcat ?HttpResponse - http-response)
    (response-in-transit-to-proxy ?HttpResponse - http-response)
    (response-received-by-proxy ?ReverseProxy - reverse-proxy ?HttpResponse - http-response)
    (response-ready-for-forwarding ?HttpResponse - http-response)
    (response-forwarded-to-attacker ?ReverseProxy - reverse-proxy ?HttpResponse - http-response)
    (response-in-transit-to-attacker ?HttpResponse - http-response)
    (response-received-by-attacker ?Attacker - attacker ?HttpResponse - http-response)
    
    (smuggling-signal-received ?Attacker - attacker)
    (can-send-smuggled-payload ?Attacker - attacker)
    (user-http-request ?UserRequest - http-request)
    (targets-sensitive-resource ?HttpRequest - http-request ?Resource - sensitive-information)
    (request-context-mixed ?Tomcat - tomcat ?HttpRequest - http-request ?UserSession - user-session)
    (session-hijack-condition ?HttpRequest - http-request ?UserSession - user-session)
    (smuggled-request-with-user-context ?HttpRequest - http-request ?UserSession - user-session)
    
    (user-session-hijacked ?HttpRequest - http-request ?UserSession - user-session)
    (smuggled-request-executed-as-user ?HttpRequest - http-request ?User - user)
    
    (sensitive-response-generated ?Tomcat - tomcat ?HttpResponse - http-response)
    (contains-sensitive-resource ?HttpResponse - http-response ?Resource - sensitive-information)
    (sensitive-response-sent-to-proxy ?HttpResponse - http-response)
    (bond-to-user-account ?User - user ?SensitiveResource - sensitive-information)
  
    (cacheable-resource ?CachedResource - cached-resource) 
    (cache-poisoning-payload ?Request - http-request ?Payload - cache-poison-payload)
    (attacker-controlled-response-payload ?Request - http-request)
    (has-cached-resource ?CachedResource - cached-resource)
    (targets-cached-resource ?Request - http-request ?CachedResource - cached-resource)
    (has-application-cache ?Application - application ?Cache - application-cache)
    (cache-injected-with-attacker-content ?Cache - application-cache ?Request - http-request)
    (poisoned-response-generated ?Tomcat - tomcat ?Response - http-response)
    (contains-attacker-injected-content ?Response - http-response ?Cache - application-cache)
    (poisoned-response-sent-to-proxy ?Response - http-response)
    (poisoned-content-delivered-to-user ?User - user)
    (cache-poisoning-condition ?SmuggledRequest - http-request ?UserSession - user-session)
    (smuggling-trigger-http-request ?TriggerRequest - http-request)
    (smuggling-http-request-http  ?SmuggledRequest - http-request)
    (smuggling-http-request-cache-poisoning  ?SmuggledRequest - http-request)
    (smuggling-http-request-hijack  ?SmuggledRequest - http-request)

 )

;;;#################################### Application vulnerability exposure action ####################################;;;
;;@start vulnerability expose@;;
;(:action application-exposes-attack-surfaces-to-attackers-CVE-2024-12798  
;  :parameters (?Application - application ?Logback - logback ?JaninoLib - java-library ?User - user ?Directory - path ?ConfigFile - logback-config) ;;?application: the target application
;  :precondition (and
;
;    ;; ==== basic environment compositions ====
;   ; 1. The application deploys logback
;    ;(has-software ?Application ?Logback) 
;    ;(logback-core ?Logback) 
;    (has-logback ?Application ?Logback)
;     
;
;    ; 2. Vulnerable Logback version (version ≤ 1.3.14 or 1.4.0 – 1.5.12)
;    (or
;      ;; version ≤ 1.3.14 
;      
;      (<= (version ?Logback) 1003014000)       ;; 1.4.0 ≤ version ≤ 1.5.12
;      (and 
;        (>= (version ?Logback) 1004000000)  
;        (<= (version ?Logback) 1005012000)  
;      )
;    )
;
;    ;3. JaninoEventEvaluator enabled
;     ;; two definition method
;    ;; aim: show the meaning that system enables JaninoEventEvaluator extension; 
;    ;; 1. respectively define object for the two entities
;    ;(feature ?Janinoevaluator)  
;    ;(has-feature ?Logback ?Janinoevaluator)  
;    ;(feature-enabled ?Logback ?Janinoevaluator)
;    ;; 2. directly show the characteristics of application
;    (janino-evaluator-enabled ?Application ?Logback)
;    
;
;    ;4. Janino library 
;    (has-library ?Application ?JaninoLib)
;     (janino-library ?JaninoLib)
;    ;(has-dependency ?Application ?JaninoLib)
;
;    ;5. Dynamic config loading enabled
;    (dynamic-config-loading-enabled ?Application ?Logback)
;
;    ;6. User has write permission on configuration directory or env variables
;    (has-config-dir ?Application ?Directory)
;    (has-access ?User ?Directory)
;    (has-write-access ?User ?Directory)
;    
;    ;7. No Janino code execution restrictions
;    (not (has-code-execution-restriction ?Application ?Logback))
;    ; No config integrity check
;    (not (has-integrity-check ?Application ?Logback ?ConfigFile))
;    (not (has-signature-verification ?Application ?Logback ?ConfigFile))
;
;    ;8. Controllable env variables (allows specifying the configuration file path via environment variables.)
;    (has-controllable-env-vars ?Application)
;  )
;  :effect (and (exposed-attack-surface ?Application CVE_2024_12798)
;               (exploit-by CVE_2024_12798 change-to-malicious-logback-config)
;               (increase (total-cost) 53)))
;;@end vulnerability expose@;;

;;@start vulnerability expose@;;
;(:action application-exposes-attack-surfaces-to-attackers-CVE-2024-38286
; :parameters (?Application - application ?Tomcat - tomcat ?TLSConnector - tls-connector)
; :precondition (and
;     ;1. system deploys Tomcat instance with TLS connector 
;     (has-tomcat ?Application ?Tomcat)
;     (tomcat-has-tls-connector ?Application ?Tomcat ?TLSConnector)
;    
;     ;2. vulnerable tomcat version 
;      (or 
;        ; Tomcat 11.0.0-M1 to M20 
;        (and 
;          (>= (version ?Tomcat) 11000000001) 
;          (<= (version ?Tomcat) 11000000020)
;        )
;        ; Tomcat 10.1.0-M1 t 10.1.24
;        (and 
;          (>= (version ?Tomcat) 10001000001) 
;          (<= (version ?Tomcat) 10001024000)
;        )
;        ; Tomcat 9.0.13 to 9.0.89
;        (and 
;          (>= (version ?Tomcat) 9000013000) 
;          (<= (version ?Tomcat) 9000089000)
;        )
;      )
;
;     ;3. system TSL supports renegotiation; TLS renegotiation is not disabled (renegotiation allowed by default)
;     (tomcat-tls-renegotiation-enabled ?Application ?Tomcat ?TLSConnector)
;     
;     ;4. system's memory is limited
;     (has-memory-limitation ?Application ?Tomcat)
;    
;    
;     ;5. No memory protection mechanisms (e.g., no OOM Killer)
;     (not (has-memory-protection-mechanisms ?Application))
;
;     ;6.  No connection rate limiting: maxConnections or firewall rules not configured
;     (not (max-connection-restriction ?Application))
;     (not (firewall-connection-restriction ?Application))
;     
;     ;7. No abnormal traffic detection (no IDS/IPS/WAF monitoring)
;     (not (IDS-monitoring ?Application))
;     (not (IPS-monitoring ?Application))
;     (not (WAF-monitoring ?Application)))  
;
;  :effect (and (exposed-attack-surface ?Application CVE_2024_38286)
;          (exploit-by CVE_2024_38286 abuse-tls-handshake)
;          (vulnerable-tomcat ?Tomcat)
;          (increase (total-cost) 29))) 
;;@end vulnerability expose@;;


;;@start vulnerability expose@;;
(:action application-exposes-attack-surfaces-to-attackers-CVE-2024-22243   
    :parameters (?Application - application ?SpringFramework - spring-framework ?Endpoint - endpoint ?Parser - url-parser)
    :precondition (and 

      ; 1. Application uses a vulnerable version of Spring Framework
      (has-dependency-on-spring-framework ?Application ?SpringFramework)
      (or 
         ; 5.3.x before 5.3.31 (5003000000 + 31000 = 5003031000)
         (and (>= (version ?SpringFramework) 5003000000) (< (version ?SpringFramework) 5003031000))
         ; 6.0.x before 6.0.16 (6000000000 + 16000 = 6000016000)
         (and (>= (version ?SpringFramework) 6000000000) (< (version ?SpringFramework) 6000016000))
         ; 6.1.x before 6.1.13 (6001000000 + 13000 = 6001013000)
         (and (>= (version ?SpringFramework) 6001000000) (< (version ?SpringFramework) 6001013000))
       )

      ;1. Application depends on vulnerable UriComponentsBuilder (e.g., specific versions of Spring Framework) 
       (has-dependency-on-vulnerable-paser ?Application ?Parser)

       
      ;2. Endpoints accept external-controlled URL parameters (e.g., /redirect?url=...)
       (has-external-settingable-endpoint ?Application ?Endpoint)

      ;3. Application supports HTTP url redirects
     (url-redirect-enabled ?Application)

      ;4. No strict validation on protocol, path, or port in received URLs
      (not (url-endpoint-setting-restriction ?Application ?Endpoint))
     ;(not (url-endpoint-protocol-restriction ?Application ?Endpoint))
     ;(not (url-endpoint-path-restriction ?Application ?Endpoint))
     ;(not (url-endpoint-points-restriction ?Application ?Endpoint))
      ;2. Application can access internal or external network resources 
      (external-resource-accessable ?Application)
      (internal-resource-accessable ?Application)

      ;5. Host validation flaws: uses blacklist instead of whitelist; fails to handle URL encoding or special characters (e.g., @, %0d%0a); lacks canonical URL parsing
      (vulnerable-host-validation ?Application)
      ;(depend-blacklist-host-validation ?Application)
      ;(not (canonicalization-parse-url ?Application))
      
      ;6. no anti-open redirect protections (e.g., Spring Security's RedirectValidator not enabled)
      (not (anti-redirect-protection ?Application))

     ;7. WAF/IPS does not block malicious redirect attempts
     (not (WAF-malicious-request-bloack ?Application))
     (not (IPS-malicious-request-bloack ?Application)) )
    :effect (and (exposed-attack-surface ?Application CVE_2024_22243)
                (exploit-by CVE_2024_22243 crafts-redirect-url)
                (exploit-by CVE_2024_22243 crafts-redirect-url-to-phishing-site)
                (exploit-by CVE_2024_22243 build-phishingsite)
                (vulnerable-spring-framework ?SpringFramework)
                (increase (total-cost) 21)))
;;@end vulnerability expose@;;  


;;@start vulnerability expose@;;
;(:action application-exposes-attack-surfaces-to-attackers-CVE-2024-38820
;   :parameters (?Application - application ?SpringFramework - spring-framework ?Config - locale-config ?DataBinder - data-binder ?Controller - web-controller ?Pattern - disallowed-pattern)  
;   :precondition (and
;      ; 1. Application uses a vulnerable version of Spring Framework
;      (has-dependency-on-spring-framework ?Application ?SpringFramework)
;     (or 
;         ; 5.3.x before 5.3.41 (5003000000 + 41000 = 5003041000)
;         (and (>= (version ?SpringFramework) 5003000000) (< (version ?SpringFramework) 5003041000))
;         ; 6.0.x before 6.0.25 (6000000000 + 25000 = 6000025000)
;         (and (>= (version ?SpringFramework) 6000000000) (< (version ?SpringFramework) 6000025000))
;         ; 6.1.x before 6.1.14 (6001000000 + 14000 = 6001014000)
;         (and (>= (version ?SpringFramework) 6001000000) (< (version ?SpringFramework) 6001014000))
;      )
;      
;      ; 2. DataBinder component is actively used for binding HTTP request parameters
;      (has-vulnerable-databinder ?Application ?Databinder)
;      (databinder-parameter-binding-enabled ?Application ?DataBinder)
;      
;      ; 3. Application has configured disallowedFields patterns in DataBinder
;      (has-disallowed-databinder-fields-configuration ?Application)
;      
;     ; 4. Server environment runs with specific locales (Turkish, Lithuanian, etc.) Application processes requests in vulnerable locale contexts
;     (has-locale-configuration ?Application ?Config)
;      (processes-requests-in-locale-context ?Application)
;      (has-locale-specific-exceptions ?Application)
;     (locale-has-special-case-conversion ?Application)
;      (has-vulnerable-locale-transformation ?Application)
;      
;      ; 5. Web controllers accept user input through HTTP requests
;      (has-web-controller-accept-http-post-user-input ?Application ?Controller)
; 
;      ; System Permissions & Path conditions
;      ; 1. Application accepts user-controlled parameter names
;      (accepts-user-controlled-parameter-names ?Application)
;            
;      ; 2. DataBinder has write access to object properties
;      (databinder-has-write-access-to-properties ?Application ?DataBinder)
;      
;      ; 3. No additional input validation layers
;      (not (databinder-has-additional-input-validation-layer ?Application ?DataBinder))
;     
;      ; System Security Mechanisms conditions
;      ; 1. Reliance on case-insensitive disallowedFields matching as primary protection
;      (databinder-relies-on-case-insensitive-field-matching ?Application ?DataBinder)
;      
;      ; 2. Locale-dependent string processing without explicit locale specification
;      (locale-dependent-string-processing ?Application)
;      (not (explicit-locale-specification-in-lowercase ?Application))
;      
;      ; 3. No additional field access controls beyond DataBinder
;      (not (has-additional-field-access-controls ?Application))
;      
;      ; 4. No request parameter name sanitization
;      (not (has-parameter-name-sanitization ?Application))
;      
;      ; 5. No WAF rules or input filters for case manipulation detection
;      (not (has-WAF-case-manipulation-rules ?Application))
;      (not (has-input-filter-case-bypass-detection ?Application))
;   )   
;   :effect (and (exposed-attack-surface ?Application CVE_2024_38820)
;                (exploit-by CVE_2024_38820 bypass-locale-specific-capitalization)
;                (exploit-by CVE_2024_38820 acquire-user-account)
;                (increase (total-cost) 63)))
;;@end vulnerability expose@;;

;;@start vulnerability expose@;;
;(:action application-exposes-attack-surfaces-to-attackers-CVE-2023-34055 
; :parameters (?Application - application ?SpringBoot - spring-boot)
; :precondition (and
;     ;1. Application runs vulnerable Spring Boot versions (2.7.0-2.7.17, 3.0.0-3.0.12, or 3.1.0-3.1.5)
;     (has-spring-boot ?Application ?SpringBoot)
;     (or 
;        ; Spring Boot 2.7.0 to 2.7.17
;        (and 
;          (>= (version ?SpringBoot) 2007000000) 
;          (<= (version ?SpringBoot) 2007017000)
;        )
;        ; Spring Boot 3.0.0 to 3.0.12
;        (and 
;          (>= (version ?SpringBoot) 3000000000) 
;          (<= (version ?SpringBoot) 3000012000)
;        )
;        ; Spring Boot 3.1.0 to 3.1.5
;        (and 
;          (>= (version ?SpringBoot) 3001000000) 
;          (<= (version ?SpringBoot) 3001005000)
;        )
;      )
;
;     ;2. Application uses Spring MVC or Spring WebFlux web framework
;     (or (spring-boot-has-mvc ?Application ?SpringBoot)
;         (spring-boot-has-webflux ?Application ?SpringBoot))
;     
;     ;3. org.springframework.boot:spring-boot-actuator dependency is present on the classpath
;     (has-actuator-dependency ?Application ?SpringBoot)
;     
;     ;4. Web metrics collection is enabled (management.metrics.enable.http.server.requests=true by default)
;     (web-metrics-enabled ?Application ?SpringBoot)
;    
;     ;5. Application accepts and processes HTTP requests from external sources
;     (accepts-external-http-requests ?Application)
;
;     ;6. No rate limiting or request throttling mechanisms are implemented
;     (not (max-connection-restriction ?Application))
;     
;     ;7. Application endpoints are accessible to attackers (no network-level filtering)
;     (actuator-endpoints-accessible ?Application)
;     (not (firewall-connection-restriction ?Application))
;     
;     ;8. Web observations and metrics gathering functionality is active
;     (web-observations-active ?Application ?SpringBoot)
;     
;     ;9. No monitoring or alerting systems detect unusual request patterns
;     (not (IDS-monitoring ?Application))
;     (not (IPS-monitoring ?Application))
;     (not (WAF-monitoring ?Application))
;     
;     ;10. Application lacks resource consumption controls or request size limits
;     (not (resource-consumption-controls ?Application))
;     (not (request-size-limits ?Application)))
;
;  :effect (and (exposed-attack-surface ?Application CVE_2023_34055)
;             (exploit-by CVE_2023_34055 craft-http-flood-script)
;            (vulnerable-spring-boot ?SpringBoot)
;            (increase (total-cost) 43))) 
;;@end vulnerability expose@;;

;;@start vulnerability expose@;;
;(:action application-exposes-attack-surfaces-to-attackers-CVE-2024-34447
; :parameters (?Application - application ?BouncyCastle - bouncy-castle ?BCJSSE - bcjsse)
; :precondition (and
;     ;1. Application uses vulnerable Bouncy Castle Java Cryptography APIs (versions before BC 1.78) with BCJSSE enabled
;     (has-bouncy-castle ?Application ?BouncyCastle)
;     (< (version ?BouncyCastle) 1078000000) ; version before 1.78
;     (bcjsse-enabled ?Application ?BouncyCastle ?BCJSSE)
;     
;     ;2. Endpoint identification is enabled in the BCJSSE configuration
;     (endpoint-identification-enabled ?Application ?BCJSSE)
;     
;     ;3. Application creates SSL sockets without explicit hostname specification
;     (ssl-socket-without-explicit-hostname ?Application)
;     
;     ;4. Application performs HTTPS connections that trigger DNS resolution during hostname verification
;    (https-connections-trigger-dns-resolution ?Application)
;     
;     ;5. No additional certificate validation mechanisms beyond BCJSSE hostname verification
;     (not (additional-certificate-validation ?Application))
;     
;     ;6. Network infrastructure allows DNS traffic interception or modification
;     (dns-traffic-interception-allowed ?Application))
;     
;  :effect (and (exposed-attack-surface ?Application CVE_2024_34447)
;          (exploit-by CVE_2024_34447 perform-dns-poisoning)
;          (exploit-by CVE_2024_34447 sets-up-malicious-server)
;          (vulnerable-bcjsse ?Application ?BCJSSE)
;          (increase (total-cost) 29)))
;;@end vulnerability expose@;;


;;@start vulnerability expose@;;
;(:action application-exposes-attack-surfaces-to-attackers-CVE-2022-40150
; :parameters (?Application - application ?JettisionLibrary - java-library ?APIEndpoint - api-endpoint ?SOAPEndpoint - soap-endpoint)
; :precondition (and
;     ;1. Application uses a vulnerable version of Jettison library (org.codehaus.jettison:jettison < 1.5.2)
;     ;(uses-library ?Application ?JettisionLibrary)
;     (has-library ?Application ?JettisionLibrary)
;     (jettison-library ?JettisionLibrary)
;     (< (version ?JettisionLibrary) 1005002000) ; version < 1.5.2
;     
;     ;2. Application accepts user-supplied XML or JSON input through exposed endpoints
;     (has-api-endpoint ?Application ?APIEndpoint)
;     (has-soap-endpoint ?Application ?SOAPEndpoint)
;     (accepts-json-input ?Application ?APIEndpoint)
;    
;     ;3. User input is directly passed to Jettison parser without input validation or size/complexity limits
;     (not (api-endpoint-has-input-validation ?Application ?APIEndpoint))
;     (not (api-endpoint-has-input-size-limits ?Application ?APIEndpoint))
;     (not (api-endpoint-has-complexity-limits ?Application ?APIEndpoint))
;     
;     ;4. No input sanitization or preprocessing to detect malicious payloads
;     (not (api-endpoint-has-input-sanitization ?Application ?APIEndpoint))
;     (not (api-endpoint-has-preprocessing-detection ?Application ?APIEndpoint))
;
;
;     ;5. Application lacks memory consumption limits or monitoring for heap memory usage during parsing operations;
;     (not (has-heap-memory-consumption-limits ?Application ))
;     (not (has-heap-memory-monitoring ?Application))
;     ;(not (has-memory-consumption-limits ?Application))
;     ;(not (has-memory-monitoring ?Application))
;     
;     ;6. Application server/container lacks sufficient heap memory isolation or resource quotas
;     (not (has-memory-protection-mechanisms ?Application))
;     (not (has-heap-memory-isolation ?Application))
;     (not (has-heap-memory-quotas ?Application))
;     
;     ;7. No rate limiting or throttling mechanisms exist
;     (not (has-rate-limiting ?Application ?APIEndpoint))
;     (not (has-throttling-mechanisms ?Application ?APIEndpoint))
;     
;     ;8. Absence of Web Application Firewall (WAF) rules (application layer firewall)
;     (not (has-waf-protection ?Application))
;     (not (has-waf-json-payload-detection ?Application)))
;
;  :effect (and (exposed-attack-surface ?Application CVE_2022_40150)
;          (vulnerable-jettison-parser ?JettisionLibrary)
;          (exploit-by CVE_2022_40150 craft-malicious-json-payload ) 
;          (exploit-by CVE_2022_40150 craft-malicious-xml-payload)
;          (increase (total-cost) 29)))
;;@end vulnerability expose@;;

;;@start vulnerability expose@;;
(:action application-exposes-attack-surfaces-to-attackers-CVE-2022-40149
 :parameters (?Application - application ?JettisionLibrary - java-library ?APIEndpoint - api-endpoint ?SOAPEndpoint - soap-endpoint)
 :precondition (and
     ;1. Application uses a vulnerable version of Jettison library (org.codehaus.jettison:jettison < 1.5.2)
     ;(uses-library ?Application ?JettisionLibrary)
     (has-library ?Application ?JettisionLibrary)
     (jettison-library ?JettisionLibrary)
     (< (version ?JettisionLibrary) 1005002000) ; version < 1.5.2
     
     ;2. Application accepts user-supplied XML or JSON input through exposed endpoints
     (has-api-endpoint ?Application ?APIEndpoint)
    (has-soap-endpoint ?Application ?SOAPEndpoint)
     (accepts-json-input ?Application ?APIEndpoint)
     
     ;3. User input is directly passed to Jettison parser without input validation or size/complexity limits
     (not (api-endpoint-has-input-validation ?Application ?APIEndpoint))
     (not (api-endpoint-has-input-size-limits ?Application ?APIEndpoint))
     (not (api-endpoint-has-complexity-limits ?Application ?APIEndpoint))
     
     ;4. No input sanitization or preprocessing to detect malicious payloads
     (not (api-endpoint-has-input-sanitization ?Application ?APIEndpoint))
     (not (api-endpoint-has-preprocessing-detection ?Application ?APIEndpoint))


     ;5. Application lacks memory consumption limits or monitoring for heap memory usage during parsing operations;
     (not (has-stack-memory-consumption-limits ?Application ))
     (not (has-stack-memory-monitoring ?Application))
     ;(not (has-memory-consumption-limits ?Application))
     ;(not (has-memory-monitoring ?Application))
     
     ;6. Application server/container lacks sufficient heap memory isolation or resource quotas
     (not (has-memory-protection-mechanisms ?Application))
     (not (has-stack-memory-isolation ?Application))
     (not (has-stack-memory-quotas ?Application))
     
     ;7. No rate limiting or throttling mechanisms exist

     (not (has-rate-limiting ?Application ?APIEndpoint))
     (not (has-throttling-mechanisms ?Application ?APIEndpoint))
     
     ;8. Absence of Web Application Firewall (WAF) rules (application layer firewall)
     (not (has-waf-protection ?Application))
     (not (has-waf-json-payload-detection ?Application)))

  :effect (and (exposed-attack-surface ?Application CVE_2022_40149)
          (exploit-by CVE_2022_40149 craft-malicious-xml-payload)
          (exploit-by CVE_2022_40149 craft-malicious-json-payload)
          (vulnerable-jettison-parser ?JettisionLibrary)
          (increase (total-cost) 29)))
;;@end vulnerability expose@;;


;;@start vulnerability expose@;;
;(:action application-exposes-attack-surfaces-to-attackers-CVE-2023-6378
; :parameters (?Application - application ?LogbackLibrary - java-library ?ReceiverComponent - logback-receiver ?TCPEndpoint - tcp-endpoint)
; :precondition (and
;
;     ;1. Application uses vulnerable logback version 1.4.11 with receiver component deployed
;     (has-library ?Application ?LogbackLibrary)
;     (logback-library ?LogbackLibrary)
;     (= (version ?LogbackLibrary) 1004011000) ; version = 1.4.11
;     (has-receiver-component ?Application ?ReceiverComponent)
;     
;     ;2. Logback receiver component is actively deployed and configured
;     (logback-receiver-deployed ?ReceiverComponent)
;     (logback-receiver-configured ?ReceiverComponent)
;     
;     ;3. Logback Receiver is configured to listen on network ports (TCP/IP)
;     (logback-receiver-has-tcp-endpoint ?Application ?TCPEndpoint)
;     (logback-receiver-listens-on-port ?ReceiverComponent ?TCPEndpoint)
;
;     ;4. Network connectivity allows external access to Logback Receiver  listening ports
;     (tcp-endpoint-external-access-allowed ?TCPEndpoint)
;     (tcp-endpoint-firewall-permits-inbound ?TCPEndpoint)
;    
;     ;5. Application deserializes untrusted data without sufficient validation
;     (not (has-deserialization-validation ?Application))
;     
;     ;6. No input sanitization or deserialization filtering mechanisms
;     (not (has-input-sanitization ?Application))
;     (not (has-deserialization-filtering ?Application))
;     
;     ;7. Logback Receiver accepts connections from unauthenticated sources
;     (not (logback-receiver-requires-authentication ?ReceiverComponent))
;     
;     ;8. Logback Receiver is configured in logback.xml to accept remote logging events
;     (logback-receiver-accepts-remote-events ?ReceiverComponent)
;     (logback-receiver-configured-in-logback-xml ?ReceiverComponent)
;     
;     ;9. No network-level protections exist
;     (not (has-waf-protection ?Application))
;     (not (has-ips-protection ?Application))
;     (not (has-serialized-payload-detection ?Application))
;     
;     ;10. Application lacks proper exception handling for deserialization failures
;     (not (has-proper-exception-handling ?Application)))
;
;  :effect (and (exposed-attack-surface ?Application CVE_2023_6378)
;          (exploit-by CVE_2023_6378 craft-malicious-serialized-payload)
;          (vulnerable-logback-receiver ?ReceiverComponent)
;          (vulnerable-receiver ?ReceiverComponent)
;          (increase (total-cost) 29)))
;;@end vulnerability expose@;;

;;@start vulnerability expose@;;
;(:action application-exposes-attack-surfaces-to-attackers-CVE-2023-44487
; :parameters (?Application - application ?Server - http2-server ?HTTPInterface - network-interface ?HTTP2Implementation - http2-library)
; :precondition (and
;     ;1. Application Server implements HTTP/2 protocol with stream multiplexing capability
;     (has-http2-implementation ?Application ?Server ?HTTP2Implementation)
;     (http2-stream-multiplexing-enabled ?Application ?Server)
     
;     ;2. Application Server accepts HTTP/2 connections on public-facing interfaces (ports 80/443)
;     (http2-server-has-network-interface ?Application ?Server ?HTTPInterface)
;     (http2-server-public-facing-interface ?Application ?HTTPInterface)
;     (or (= (port ?HTTPInterface) 80) 
;         (= (port ?HTTPInterface) 443)
;     )
;     (http2-connections-accepted ?Application ?HTTPInterface)
     
;     ;3. Application HTTP/2 server processes HEADERS and RST_STREAM frames without proper rate limiting
;     (http2-server-processes-headers-frames ?Server)
;     (http2-server-processes-rst-stream-frame ?Server)
;     (not (http2-server-has-frame-rate-limiting ?Server))
     
;      ;4. Application Server allocates resources for each stream
;     (http2-server-allocates-stream-resources ?Application ?Server)
;     (http2-server-allocates-header-parsing-resources ?Application ?Server)
;     (http2-server-allocates-url-mapping-resources ?Application ?Server)
     
;     ;5. Application Server allows RST_STREAM frames immediately after request frames
;     (http2-server-allows-immediate-rst-stream ?Application ?Server)
;     (not (http2-server-requires-stream-coordination ?Application ?Server))
     
;     ;6. Application Server does not enforce limits on canceled requests per connection
;     (not (http2-server-enforces-canceled-request-limits ?Application ?Server))
;     (http2-server-canceled-requests-not-counted-toward-limits ?Application ?Server)
     
;     ;7. Application Server lacks connection-level tracking of rapid patterns
;     (not (http2-server-has-connection-level-pattern-tracking ?Application ?Server))
;     (not (http2-server-detects-rapid-creation-cancellation-patterns ?Application ?Server))
     
;     ;8. Application Server maintains HTTP/2 connections open after stream cancellations
;     (http2-server-maintains-connections-after-cancellation ?Application ?Server)
;     (http2-server-allows-indefinite-stream-creation ?Application ?Server)
     
;     ;9. Application Absence of GOAWAY frame implementation for abuse detection
;     (not (http2-server-implements-goaway-frame-abuse-detection ?Application ?Server))
;     (not (http2-server-has-immediate-connection-termination ?Application ?Server))
     
;     ;10. Application Server runs vulnerable HTTP/2 implementation
;     (or (and (http2-server-nodejs-implementation ?HTTP2Implementation) 
;              (or (= (version ?HTTP2Implementation) 18000000000) 
;                  (= (version ?HTTP2Implementation) 20000000000)))
;         (and (http2-server-nghttp2-implementation ?HTTP2Implementation) 
;              (<= (version ?HTTP2Implementation) 1057000000))
;         (and (http2-server-netty-implementation ?HTTP2Implementation) 
;              (<= (version ?HTTP2Implementation) 4001100000))
;         (http2-server-envoy-implementation ?HTTP2Implementation)
;         (http2-server-eclipse-jetty-implementation ?HTTP2Implementation)
;         (and (http2-server-caddy-implementation ?HTTP2Implementation) 
;              (<= (version ?HTTP2Implementation) 2007005000)))      
;     
;     ;11. No DDoS protection mechanisms for HTTP/2 rapid reset patterns
;     (not (http2-server-has-rapid-reset-ddos-protection ?Application ?Server))
;     (not (http2-server-has-rapid-reset-pattern-detection ?Application ?Server))
     
;     ;12. Server resource limits insufficient for amplified consumption
;     (insufficient-resource-limits ?Application ?Server)
;     (not (http2-server-can-handle-rapid-allocation-cancellation-cycles ?Application ?Server)))
;
;  :effect (and (exposed-attack-surface ?Application CVE_2023_44487)
;               (exploit-by CVE_2023_44487 reset-http2-streams)
;               (vulnerable-http2-server ?Server)
;               (http2-server-rapid-reset-attack-possible ?Server)
;               (rapid-reset-attack-possible ?Server)
;               (increase (total-cost) 29)))
;;@end vulnerability expose@;;


;;@start vulnerability expose@;;
;(:action application-exposes-attack-surfaces-to-attackers-CVE-2025-22228
;  :parameters (?Application - application ?SpringSecurity - spring-security ?PasswordEncoder - password-encoder)
;  :precondition (and
;    ; 1. Application uses vulnerable versions of Spring Security
;    (has-dependency-on-spring-security ?Application ?SpringSecurity)
;    (or
;      ; 5.7.0-5.7.15 (5007000000 to 5007015000)
;      (and (>= (version ?SpringSecurity) 5007000000) (<= (version ?SpringSecurity) 5007015000))
;      ; 5.8.0-5.8.17 (5008000000 to 5008017000)
;      (and (>= (version ?SpringSecurity) 5008000000) (<= (version ?SpringSecurity) 5008017000))
;      ; 6.0.0-6.0.15 (6000000000 to 6000015000)
;      (and (>= (version ?SpringSecurity) 6000000000) (<= (version ?SpringSecurity) 6000015000))
;      ; 6.1.0-6.1.13 (6001000000 to 6001013000)
;      (and (>= (version ?SpringSecurity) 6001000000) (<= (version ?SpringSecurity) 6001013000))
;      ; 6.2.0-6.2.9 (6002000000 to 6002009000)
;      (and (>= (version ?SpringSecurity) 6002000000) (<= (version ?SpringSecurity) 6002009000))
;      ; 6.3.0-6.3.7 (6003000000 to 6003007000)
;      (and (>= (version ?SpringSecurity) 6003000000) (<= (version ?SpringSecurity) 6003007000))
;      ; 6.4.0-6.4.3 (6004000000 to 6004003000)
;      (and (>= (version ?SpringSecurity) 6004000000) (<= (version ?SpringSecurity) 6004003000))
;    )
;    ; 2. Authentication mechanism uses BCryptPasswordEncoder for password verification
;    (use-bcrypt-password-encoder ?Application ?PasswordEncoder)
;    ; 3. System allows or accepts user passwords longer than 72 characters
;    (allows-long-passwords ?Application)
;    (not (password-length-validation ?Application))
;    ; 5. No additional authentication factors are required (no MFA/2FA enforcement)
;    (not (multi-fator-auth-enabled ?Application))
;    (not (two-factor-auth-enabled ?Application))
;    ; 6. No password length validation or truncation warnings are implemented
;    (not (password-truncation-warning ?Application))
;    ; 7. No compensating controls
;    (not (account-lockout-policy ?Application))
;    (not (rate-limiting-enabled ?Application))
;    (not (anomaly-detection-enabled ?Application))
;    ; 8. Application does not implement pre-hashing mechanisms
;    (not (pre-hashing-implemented ?Application))
;    (not (sha256-pre-hash-enabled ?Application))
;  )
;  :effect (and (exposed-attack-surface ?Application CVE_2025_22228)
;         (vulnerable-password-validation ?Application)
;         (exploit-by CVE_2025_22228 online-brute-force)
;         (increase (total-cost) 30)))
;;@end vulnerability expose@;;


;;@start vulnerability expose@;;
;(:action application-exposes-attack-surfaces-to-attackers-CVE-2024-38816
;    :parameters (?Application - application ?SpringFramework - spring-framework 
;                 ?RouterFunction - router-function ?ResourceHandler - resource-handler
;                 ?FileSystemResource - filesystem-resource ?CVEID - cve-identifier)
;    :precondition (and 
;      ; 1. Application uses vulnerable version of Spring Framework (5.3.0 to 5.3.39, 6.0.0 to 6.0.23, 6.1.0 to 6.1.12)
;      (has-dependency-on-spring-framework ?Application ?SpringFramework)
;      (or 
;         ; 5.3.0 to 5.3.39 (5003000000 to 5003039000)
;         (and (>= (version ?SpringFramework) 5003000000) (<= (version ?SpringFramework) 5003039000))
;         ; 6.0.0 to 6.0.23 (6000000000 to 6000023000)
;         (and (>= (version ?SpringFramework) 6000000000) (<= (version ?SpringFramework) 6000023000))
;         ; 6.1.0 to 6.1.12 (6001000000 to 6001012000)
;         (and (>= (version ?SpringFramework) 6001000000) (<= (version ?SpringFramework) 6001012000))
;       )
;      
;      ; 2. Application uses functional web frameworks WebMvc.fn or WebFlux.fn for serving static resources
;     (or (uses-WebMvc-web-framework ?Application)
;         (uses-WebFlux-web-framework ?Application))
;      
;      ; 3. Application explicitly configures RouterFunctions to serve static resources
;      (has-router-function-configured ?Application ?RouterFunction)
;      (router-function-serves-static-resources ?RouterFunction)
;      
;      ; 4. Resource handling configured with FileSystemResource location
;      (has-filesystem-resource-configured ?Application ?FileSystemResource)
;      (points-to-filesystem-path ?FileSystemResource)
;      
;      ; 5. Application process has read access to sensitive files
;      (has-filesystem-read-access ?Application)
;      (sensitive-files-accessible ?Application)
;      
;      ; 6. Spring Security HTTP Firewall is NOT enabled
;      (not (spring-security-http-firewall-enabled ?Application))
;
;      
;      ; 7. NOT running on Tomcat or Jetty (which would block malicious requests)
;      (not (runs-on-tomcat ?Application))
;      (not (runs-on-jetty ?Application))
;      
;      ; 8. No input validation for URL path parameters
;      (not (url-path-validation-enabled ?Application))
;      
;      ; 9. No WAF rules for path traversal detection
;      (not (has-WAF-path-traversal-protection ?Application))
;      
;      ; 10. File system permissions allow reading outside intended directory
;      (filesystem-permissions-allow-traversal ?Application))
;    :effect (and (exposed-attack-surface ?Application CVE_2024_38816)
;             (exploit-by CVE_2024_38816 path-traversal)
;            (increase (total-cost) 29)))
;;@end vulnerability expose@;;


;;@start vulnerability expose@;;
;(:action application-exposes-attack-surfaces-to-attackers-CVE-2022-1471   
;    :parameters (?Application - application ?SnakeYAML - snakeyaml-library ?Java - software ?Endpoint - yaml-endpoint)
;    :precondition (and 
;      ; 1. Application uses vulnerable SnakeYAML version (prior to 2.0, specifically 1.30-1.33)
;      (has-dependency-on-snakeyaml ?Application ?SnakeYAML)
;      (and (>= (version ?SnakeYAML) 1030000) (< (version ?SnakeYAML) 2000000)) ; versions 1.30+ to < 2.0
;      
;      ; 2. Java version vulnerable to JNDI injection (≤ 8u190 or ≤ 11.0.0)
;      (implementated-by-java ?Application ?Java)
;      (or 
;        (and (>= (version ?Java) 8000000) (<= (version ?Java) 8000190))
;        (and (>= (version ?Java) 11000000) (<= (version ?Java) 11000000))
;      )
;      
;      ; 3. Application accepts external YAML content from untrusted sources
;      (has-external-yaml-endpoint ?Application ?Endpoint)
;      (accepts-untrusted-yaml-input ?Application)
;      
;      ; 4. No input validation on YAML content
;      (not (has-yaml-input-validation ?Application))
;      
;      ; 5. Uses default Constructor() instead of SafeConstructor
;      (uses-default-constructor ?Application)
;      (not (uses-safe-constructor ?Application))
;      
;      ; 6. No type restrictions during deserialization
;      (not (has-yaml-type-restrictions ?Application))
;      
;      ; 7. Sufficient privileges for code execution
;      (has-sufficient-code-execution-privilege ?Application)
;      
;      ; 8. No security controls preventing dangerous class instantiation
;      (not (has-dangerous-class-instantiation-prevention ?Application))
;      
;      ; 9. No sandbox restrictions
;      (not (has-sandbox-restrictions ?Application))
;      
;      ; 10. Network connectivity for exfiltration
;      (network-connectivity-available ?Application)
;    )
;    :effect (and (exposed-attack-surface ?Application CVE_2022_1471)
;                 (exploit-by CVE_2022_1471 craft-malicious-java-class )
;                 (exploit-by CVE_2022_1471 yaml-deserialization)
;                 (exploit-by CVE_2022_1471 jndi-injection)
;                 (increase (total-cost) 2)))
;;@end vulnerability expose@;;

;;@start vulnerability expose@;;
;(:action application-exposes-attack-surfaces-to-attackers-CVE-2025-24813
;    :parameters (?Application - application ?Tomcat - tomcat ?DefaultServlet - default-servlet 
;                 ?SensitiveFile - sensitive-file ?PublicDir - public-directory ?SensitiveDir - sensitive-directory)
;    :precondition (and 
;        ;; 1. Application runs vulnerable Apache Tomcat versions
;        (has-tomcat ?Application ?Tomcat)
;        (or 
;            ;; 11.0.0-M1 through 11.0.2 (versions 11000000001 to 11000002000)
;            (and (>= (version ?Tomcat) 11000000001) (<= (version ?Tomcat) 11000002000))
;            ;; 10.1.0-M1 through 10.1.34 (versions 10001000001 to 10001034000)
;            (and (>= (version ?Tomcat) 10001000001) (<= (version ?Tomcat) 10001034000))
;            ;; 9.0.0.M1 through 9.0.98 (versions 9000000001 to 9000098000)
;            (and (>= (version ?Tomcat) 9000000001) (<= (version ?Tomcat) 9000098000))
;        )

;        ;; 2. Tomcat Server's Default servlet has write permissions enabled - writes enabled for the default servlet (disabled by default)
;        (tomcat-has-default-servlet ?Application ?DefaultServlet)
;        (tomcat-default-servlet-write-enabled ?Application ?DefaultServlet)

;        ;; 3. Partial PUT request support is enabled (enabled by default) - support for partial PUT (enabled by default) 
;        (partial-put-request-enabled ?Application)

;        ;; 4. Attacker has knowledge of public upload directories
;        (has-public-directory ?Application ?PublicDir)
;        (public-directory-exposed ?Application ?PublicDir)

;        ;; distinguished preconditions for information disclosure and elevation of priviledge (RCE)
;        (or 
;          (and ;;for information disclosure
;           ;; 5. Security sensitive directories are sub-directories of public directories - a target URL for security sensitive uploads that was a sub-directory of a target URL for public uploads  
;           (public-directory-has-sensitive-subdirectory ?PublicDir ?SensitiveDir)
;           (located-at ?SensitiveFile ?SensitiveDir)
;           ;; 6. Attacker has knowledge of sensitive filenames - attacker knowledge of the names of security sensitive files being uploaded 
;           (sensitive-filename-exposed ?Application ?SensitiveFile)
;           ;; 7. security sensitive files are uploaded via partial PUT requests - the security sensitive files also being uploaded via partial put
;           (sensitive-file-partial-put-uploaded-enabled ?Application ?SensitiveFile)
;          )
;          (and ;;for code excution
;           ;; 8. For remote code execution: application uses Tomcat's file-based session persistence with default storage location -  application was using Tomcat's file based session persistence with the default storage location 
;           (tomcat-file-based-session-persistence-enabled ?Application ?Tomcat) 
;           (tomcat-default-session-storage-location ?Application ?Tomcat)
;           ;; (a future interface combine deserialization vulnerability) 9. application classpath includes libraries vulnerable to deserialization attacks (e.g., Apache Commons Collections, fastjson);
;          )
;        )
;        ;; 10. HTTP PUT method accessible to unauthenticated users
;        (http-put-method-accessible ?Application)
        
;        ;; 11. No WAF or security controls blocking malicious PUT requests
;        (not (WAF-malicious-request-block ?Application))
;        (not (security-controls-path-manipulation ?Application))
        
;        ;; 12. Application processes filenames with internal dots without proper normalization
;        (not (has-proper-path-normalization-for-filename ?Application))
;        (not (has-proper-path-equivalence-validation-for-filename ?Application))
;    )
;    :effect (and 
;        (exposed-attack-surface ?Application CVE_2025_24813)
;        (exploit-by CVE_2025_24813 internal-dot-path-manipulation)
;        (exploit-by CVE_2025_24813 craft-partial-put-request)
;        (exploit-by CVE_2025_24813 craft-malicious-web-shell)
;        (vulnerable-tomcat-default-servlet ?Tomcat ?DefaultServlet) 
;        (increase (total-cost) 2)))
;;@end vulnerability expose@;;


;;@start vulnerability expose@;;
;(:action application-exposes-attack-surfaces-to-attackers-CVE-2024-22259 
;    :parameters (?Application - application ?SpringFramework - spring-framework ?Endpoint - endpoint ?Parser - url-parser)
;    :precondition (and 
;
;      ; 1. Application uses a vulnerable version of Spring Framework
;      (has-dependency-on-spring-framework ?Application ?SpringFramework)
;      (or 
;         ; 5.3.x before 5.3.31 (5003000000 + 31000 = 5003031000)
;         (and (>= (version ?SpringFramework) 5003000000) (< (version ?SpringFramework) 5003031000))
;         ; 6.0.x before 6.0.16 (6000000000 + 16000 = 6000016000)
;         (and (>= (version ?SpringFramework) 6000000000) (< (version ?SpringFramework) 6000016000))
;         ; 6.1.x before 6.1.13 (6001000000 + 13000 = 6001013000)
;         (and (>= (version ?SpringFramework) 6001000000) (< (version ?SpringFramework) 6001013000))
;       )
;
;      ;1. Application depends on vulnerable UriComponentsBuilder (e.g., specific versions of Spring Framework) 
;       (has-dependency-on-vulnerable-paser ?Application ?Parser)
;
;       
;      ;2. Endpoints accept external-controlled URL parameters (e.g., /redirect?url=...)
;       (has-external-settingable-endpoint ?Application ?Endpoint)
;
;      ;3. Application supports HTTP url redirects
;     (url-redirect-enabled ?Application)
;
;      ;4. No strict validation on protocol, path, or port in received URLs
;      (not (url-endpoint-setting-restriction ?Application ?Endpoint))
;     ;(not (url-endpoint-protocol-restriction ?Application ?Endpoint))
;     ;(not (url-endpoint-path-restriction ?Application ?Endpoint))
;     ;(not (url-endpoint-points-restriction ?Application ?Endpoint))
;      ;2. Application can access internal or external network resources 
;      (external-resource-accessable ?Application)
;      (internal-resource-accessable ?Application)
;
;      ;5. Host validation flaws: uses blacklist instead of whitelist; fails to handle URL encoding or special characters (e.g., @, %0d%0a); lacks canonical URL parsing
;      (vulnerable-host-validation ?Application)
;      ;(depend-blacklist-host-validation ?Application)
;      ;(not (canonicalization-parse-url ?Application))
;      
;      ;6. no anti-open redirect protections (e.g., Spring Security's RedirectValidator not enabled)
;      (not (anti-redirect-protection ?Application))

;     ;7. WAF/IPS does not block malicious redirect attempts
;    (not (WAF-malicious-request-bloack ?Application))
;     (not (IPS-malicious-request-bloack ?Application)) )
;    :effect (and (exposed-attack-surface ?Application CVE_2024_22259)
;                (exploit-by CVE_2024_22259 crafts-redirect-url)
;                (exploit-by CVE_2024_22259 crafts-redirect-url-to-phishing-site)
;                (exploit-by CVE_2024_22259 build-phishingsite)
;                (increase (total-cost) 21)))
;;@end vulnerability expose@;; 


;;@start vulnerability expose@;;
;(:action application-exposes-attack-surfaces-to-attackers-CVE-2024-22262 
;    :parameters (?Application - application ?SpringFramework - spring-framework ?Endpoint - endpoint ?Parser - url-parser)
;    :precondition (and 
;
;      ; 1. Application uses a vulnerable version of Spring Framework
;      (has-dependency-on-spring-framework ?Application ?SpringFramework)
;      (or 
;         ; 5.3.x before 5.3.31 (5003000000 + 31000 = 5003031000)
;         (and (>= (version ?SpringFramework) 5003000000) (< (version ?SpringFramework) 5003031000))
;         ; 6.0.x before 6.0.16 (6000000000 + 16000 = 6000016000)
;         (and (>= (version ?SpringFramework) 6000000000) (< (version ?SpringFramework) 6000016000))
;         ; 6.1.x before 6.1.13 (6001000000 + 13000 = 6001013000)
;         (and (>= (version ?SpringFramework) 6001000000) (< (version ?SpringFramework) 6001013000))
;       )
;
;      ;1. Application depends on vulnerable UriComponentsBuilder (e.g., specific versions of Spring Framework) 
;       (has-dependency-on-vulnerable-paser ?Application ?Parser)
;
;
;      ;2. Endpoints accept external-controlled URL parameters (e.g., /redirect?url=...)
;       (has-external-settingable-endpoint ?Application ?Endpoint)
;
;      ;3. Application supports HTTP url redirects
;     (url-redirect-enabled ?Application)
;
;      ;4. No strict validation on protocol, path, or port in received URLs
;      (not (url-endpoint-setting-restriction ?Application ?Endpoint))
;     ;(not (url-endpoint-protocol-restriction ?Application ?Endpoint))
;     ;(not (url-endpoint-path-restriction ?Application ?Endpoint))
;     ;(not (url-endpoint-points-restriction ?Application ?Endpoint))
;      ;2. Application can access internal or external network resources 
;      (external-resource-accessable ?Application)
;      (internal-resource-accessable ?Application)
;
;      ;5. Host validation flaws: uses blacklist instead of whitelist; fails to handle URL encoding or special characters (e.g., @, %0d%0a); lacks canonical URL parsing
;      (vulnerable-host-validation ?Application)
;      ;(depend-blacklist-host-validation ?Application)
;      ;(not (canonicalization-parse-url ?Application))
;      
;      ;6. no anti-open redirect protections (e.g., Spring Security's RedirectValidator not enabled)
;      (not (anti-redirect-protection ?Application))
;
;     ;7. WAF/IPS does not block malicious redirect attempts
;    (not (WAF-malicious-request-bloack ?Application))
;     (not (IPS-malicious-request-bloack ?Application)) )
;    :effect (and (exposed-attack-surface ?Application CVE_2024_22262)
;                (exploit-by CVE_2024_22262 crafts-redirect-url)
;                (exploit-by CVE_2024_22262 crafts-redirect-url-to-phishing-site)
;                (exploit-by CVE_2024_22262 build-phishingsite)
;                (increase (total-cost) 21)))
;;@end vulnerability expose@;; 


;;@start vulnerability expose@;;
;(:action application-exposes-attack-surfaces-to-attackers-CVE-2023-2976
;    :parameters (?Application - application ?Guava - java-library ?Host - host-os)
;    :precondition (and 
;        ; 1. The application's classpath includes Google Guava version 1.0 through 31.1
;        (has-library ?Application ?Guava)
;        (guava-library ?Guava)
;        (and (>= (version ?Guava) 1000000000) (<= (version ?Guava) 31001000000)) ; version 1.0 to 31.1
;        
;        ; 2. The application's code invokes FileBackedOutputStream(int) or FileBackedOutputStream(int, boolean)
;        (uses-filebackedoutputstream ?Application)
;        
;        ; 3. The invoked FileBackedOutputStream calls File.createTempFile without a controlled parent directory
;        (uses-uncontrolled-createtempfile ?Application)
;        
;        ; 4. The application's runtime java.io.tmpdir is set to a world-writable directory
;        (java-tmpdir-set-to-world-writable ?Application)
;        
;        ; 5. The application's host OS umask and /tmp permissions allow other local users to access files
;        (has-os ?Application ?Host)
;        (world-readable-tempdir-permissions ?Host)
;        (world-writable-tempdir-permissions ?Host)
;        
;        ; 6. The application is not isolated by container or OS sandbox
;        (not (container-isolated ?Application))
;        (not (os-sandbox-isolated ?Application))
;        
;        ; 7. The application does not override temp-file creation to per-user directory
;        (not (uses-per-user-temp-directory ?Application))
;        
;        ; 8. The application's host filesystem has no ACLs or mount options restricting access
;        (not (temp-directory-acl-protected ?Application))
;        (not (temp-directory-mount-restricted ?Application))
;        
;        ; 9. The application's use of File.createTempFile yields default, guessable filenames
;        (uses-predictable-temp-filenames ?Application)
;        
;        ; 10. The application writes sensitive data into FileBackedOutputStream temporary files
;        (writes-sensitive-data-to-temp ?Application)
;    )
;    :effect (and 
;        (exposed-attack-surface ?Application CVE_2023_2976)
;        (exploit-by CVE_2023_2976 temp-file-prediction)
;        (exploit-by CVE_2023_2976 temp-file-access)
;        (vulnerable-java-library ?Guava)
;        (increase (total-cost) 34)))
;;@end vulnerability expose@;; 

;;@start vulnerability expose@;;
;(:action application-exposes-attack-surfaces-to-attackers-CVE-2024-38809
; :parameters (?Application - application ?SpringFramework - spring-framework ?HTTPEndpoint - http-endpoint ?ETagHandler - etag-handler)
; :precondition (and
;     ;; 1. Application uses vulnerable Spring Framework spring-web module
;     (has-framework ?Application ?SpringFramework)
;     (spring-web-module ?SpringFramework)
;     (or (and (>= (version ?SpringFramework) 6001000000) (<= (version ?SpringFramework) 6001011000))
;         (and (>= (version ?SpringFramework) 6000000000) (<= (version ?SpringFramework) 6000022000))
;         (and (>= (version ?SpringFramework) 5003000000) (<= (version ?SpringFramework) 5003037000))
;         (< (version ?SpringFramework) 5003000000))
;     
;     ;; 2. Application processes ETags from If-Match or If-None-Match headers
;     (has-http-endpoint ?Application ?HTTPEndpoint)
;     (has-etag-handler ?Application ?ETagHandler)
;     (processes-if-match-headers ?Application ?ETagHandler)
;     (processes-if-none-match-headers ?Application ?ETagHandler)
;     
;     ;; 3. ETag parsing logic lacks proper validation
;     (not (has-etag-validation ?Application ?ETagHandler))
;     (not (has-etag-size-limits ?Application ?ETagHandler))
;     (not (has-etag-complexity-limits ?Application ?ETagHandler))
;     
;     ;; 4. Application exposes HTTP endpoints to untrusted users
;     (publicly-accessible ?HTTPEndpoint)
;     (not (has-restrictive-access-controls ?HTTPEndpoint))
;     
;     ;; 5. No size limits on If-Match or If-None-Match headers
;     (not (has-header-size-limits ?Application ?HTTPEndpoint))
;     (not (has-framework-header-limits ?SpringFramework))
;     (not (has-servlet-container-limits ?Application))
;     
;     ;; 6. No rate limiting or request throttling
;     (not (has-http-rate-limiting ?Application ?HTTPEndpoint))
;     (not (has-request-throttling ?Application ?HTTPEndpoint))
;     
;     ;; 7. No custom input validation filters
;     (not (has-input-validation-filters ?Application))
;     (not (has-etag-validation-middleware ?Application))
;     
;     ;; 8. No WAF/IPS protection
;     (not (has-waf-protection ?Application))
;     (not (has-ips-protection ?Application))
;     (not (has-etag-header-detection-rules ?Application))
;     
;     ;; 9. Shared server resources without isolation
;     (has-shared-resources ?Application)
;     (not (has-resource-isolation ?Application))
;     
;     ;; 10. Shared thread pool across endpoints
;     (has-shared-thread-pool ?Application)
;     (not (has-endpoint-isolation ?Application)))
; :effect (and (exposed-attack-surface ?Application CVE_2024_38809)
;              (vulnerable-etag-parsing ?SpringFramework)
;              (exploit-by CVE_2024_38809 craft-malicious-etag-header)
;              (increase (total-cost) 63)))
;;@end vulnerability expose@;; 


;;@start vulnerability expose@;;
;(:action application-exposes-attack-surfaces-to-attackers-CVE-2024-47072
; :parameters (?Application - application ?XStreamLibrary - java-library ?BinaryDriver - binary-stream-driver ?APIEndpoint - api-endpoint)
; :precondition (and
;     ;1. Application uses vulnerable XStream version (1.4.20 or earlier)
;     (has-library ?Application ?XStreamLibrary)
;     (xstream-library ?XStreamLibrary)
;     (<= (version ?XStreamLibrary) 1004020000) ; version <= 1.4.20
;     
;     ;2. Application configures XStream to use BinaryStreamDriver
;     (has-binary-stream-driver ?Application ?BinaryDriver)
;     (binary-stream-driver ?BinaryDriver)
;     (xstream-uses-driver ?XStreamLibrary ?BinaryDriver)
;    
;     ;3. Application accepts and processes attacker-controlled binary input streams
;     (has-api-endpoint ?Application ?APIEndpoint)
;     (accepts-binary-input ?Application ?APIEndpoint)
;     (processes-untrusted-input ?Application ?APIEndpoint)
;     
;     ;4. Application lacks robust input validation or integrity checks
;     (not (api-endpoint-has-input-validation ?Application ?APIEndpoint))
;     (not (api-endpoint-has-integrity-checks ?Application ?APIEndpoint))
;     
;     ;5. Application does not implement StackOverflowError exception handling
;     (not (has-stackoverflow-exception-handling ?Application))
;     
;     ;6. Application's runtime permits deeply nested structures without safeguards
;     (not (has-defense-in-depth-safeguards ?Application))
;     (not (has-recursive-structure-limits ?Application))
;     
;     ;7. Application lacks effective JVM stack size restrictions
;     (not (has-jvm-stack-size-restrictions ?Application))
;     (not (has-sufficient-stack-limits ?Application))
;     
;     ;8. Application lacks limits on input stream size or complexity
;     (not (has-input-stream-size-limits ?Application))
;     (not (has-structural-complexity-limits ?Application))
;     
;     ;9. Application lacks compensating security mechanisms
;     (not (has-sandboxing ?Application))
;     (not (has-deserialization-whitelist ?Application))
;     (not (has-waf-binary-filtering ?Application)))
; :effect (and (exposed-attack-surface ?Application CVE_2024_47072)
;              (vulnerable-xstream-binary-driver ?XStreamLibrary)
;              (exploit-by CVE_2024_47072 craft-malicious-binary-payload) 
;              (increase (total-cost) 29)))
;;@end vulnerability expose@;; 

;;@start vulnerability expose@;;
(:action application-exposes-attack-surfaces-to-attackers-CVE-2023-33202
 :parameters (?Application - application
              ?BCLibrary - java-library
              ?PEMEndpoint - pem-endpoint)
 :precondition (and
    ; 1. vulnerable Bouncy Castle present
    (has-library ?Application ?BCLibrary)
    (bouncycastle-library ?BCLibrary)
    (< (version ?BCLibrary) 1007300000) ; version < 1.73.0

    ; 2. application code invokes or forwards to PEMParser
    (uses-pemparser ?Application)

    ; 3. application exposes interface(s) that accept PEM/ASN.1 input
    (has-pem-endpoint ?Application ?PEMEndpoint)
    (accepts-pem-input ?Application ?PEMEndpoint)

    ; 4. parsing performed in-process on same JVM heap
    (parser-in-process ?Application)
    (parser-shares-jvm-heap ?Application)

    ; 5. no effective pre-validation/ASN.1 structural checks
    (not (endpoint-has-content-type-enforcement ?Application ?PEMEndpoint))
    (not (endpoint-has-asn1-sanity-checks ?Application ?PEMEndpoint))
    (not (endpoint-rejects-suspicious-pem-patterns ?Application ?PEMEndpoint))

    ; 6. lacks request/resource controls (file-size, depth, timeouts, per-request caps)
    (not (endpoint-has-file-size-limits ?Application ?PEMEndpoint))
    (not (endpoint-has-asn1-depth-limits ?Application ?PEMEndpoint))
    (not (endpoint-has-parser-timeouts ?Application ?PEMEndpoint))
    (not (endpoint-has-per-request-memory-caps ?Application ?PEMEndpoint))

    ; 7. endpoints reachable with low/no privileges or insufficient rate-limiting
    (endpoint-reachable-to-attackers ?Application ?PEMEndpoint)
    (not (endpoint-rate-limited ?Application ?PEMEndpoint))

    ; 8. JVM/container runtime lacks heap isolation / cgroup limits
    (not (has-cgroup-memory-limit ?Application))
    (not (has-pod-memory-limit ?Application))
    (single-jvm-hosting-critical-services ?Application)

    ; 9. no sandboxing or process isolation for untrusted parsing
    (not (parsing-sandboxed ?Application))

    ; 10. error handling does not gracefully contain OutOfMemoryError
    (not (has-circuit-breaker-for-oom ?Application))
    (not (graceful-degradation-on-oom ?Application))

    ; 11. no upstream protections (WAF / upload policies / scanners)
    (not (has-waf-protection ?Application))
    (not (has-upload-policy-scanner ?Application ?PEMEndpoint)) )
 :effect (and
    (exposed-attack-surface ?Application CVE_2023_33202)
    (vulnerable-bouncycastle ?BCLibrary)
    (vulnerable-pemparser-in-process ?Application)
    (exploit-by CVE_2023_33202 craft-malicious-pem-payload)
    (exploit-by CVE_2023_33202 craft-malicious-pem-file)
    (exploit-needs-user-account CVE_2023_33202)
    (increase (total-cost) 60)))
;;@end vulnerability expose@;; 

;;@start vulnerability expose@;;
(:action application-exposes-attack-surfaces-to-attackers-CVE-2023-46589
 :parameters (?Application - application ?Tomcat - tomcat ?ReverseProxy - reverse-proxy ?Endpoint - http-endpoint)
 :precondition (and
     ; 1. Application runs on vulnerable Apache Tomcat versions
     (has-tomcat ?Application ?Tomcat)
     (or (and (>= (version ?Tomcat) 8005000000) (<= (version ?Tomcat) 8005095000))  ; 8.5.0-8.5.95
         (and (>= (version ?Tomcat) 9000000000) (<= (version ?Tomcat) 9000082000))  ; 9.0.0-M1-9.0.82
         (and (>= (version ?Tomcat) 10001000000) (<= (version ?Tomcat) 10001015000)) ; 10.1.0-M1-10.1.15
         (and (>= (version ?Tomcat) 11000000000) (<= (version ?Tomcat) 11000010000))) ; 11.0.0-M1-11.0.0-M10
     
     ; 2. Application is deployed behind a reverse proxy/load balancer
     (has-reverse-proxy ?Application ?ReverseProxy)
     (forwards-requests ?ReverseProxy ?Tomcat)
     
     ; 3. Application accepts HTTP/1.1 requests with Transfer-Encoding: chunked
     (accepts-chunked-encoding ?Application)
     (permits-trailer-headers ?ReverseProxy)
     
     ; 4. Mismatched parsing between reverse proxy and Tomcat
     (mismatched-parsing ?ReverseProxy ?Tomcat)
     (mismatched-trailer-handling ?ReverseProxy ?Tomcat)
     (mismatched-header-limits ?ReverseProxy ?Tomcat)
     
     ; 5. Reverse proxy forwards trailer header bytes without normalization
     (not (normalizes-trailer-headers ?ReverseProxy))
     (not (rejects-oversized-trailers ?ReverseProxy))
     (not (truncates-oversized-trailers ?ReverseProxy))
     
     ; 6. Backend connection allows reuse/keep-alive/pipelining
     (allows-connection-reuse ?ReverseProxy ?Tomcat)
     (allows-keep-alive ?ReverseProxy ?Tomcat)
     (allows-pipelining ?ReverseProxy ?Tomcat)
     
     ; 7. Application exposes target endpoints reachable by attacker
     (has-http-endpoint ?Application ?Endpoint)
     (publicly-accessible ?Endpoint)
     
     ; 8. Endpoints do not enforce strict per-request authentication
     (not (strict-per-request-auth ?Endpoint))
     
     ; 9. Application lacks request smuggling detection mechanisms
     (not (has-waf-smuggling-detection ?Application))
     (not (has-ips-oversized-trailer-rules ?Application))
     (not (rejects-malformed-trailers ?ReverseProxy))
     (not (has-request-canonicalization ?Application)))
  :effect (and (exposed-attack-surface ?Application CVE_2023_46589)
          (vulnerable-tomcat ?Tomcat)
          (exploit-by CVE_2023_46589 http-request-smuggling)
          (increase (total-cost) 28)))
;;@end vulnerability expose@;;

;;;#################################### Infrastructure vulnerability exposure action ####################################;;;
;; DNS infrastructure exposes attack surface
(:action dns-infrastructure-exposes-attack-surfaces-to-attackers
 :parameters (?DNSServer - dns-server)
 :precondition (and
     ;1. DNS server lacks DNSSEC validation capability or has DNSSEC disabled
     (not (dnssec-enabled ?DNSServer))
     
     ;2. DNS server uses predictable source port assignments
     (dns-predictable-source-ports ?DNSServer)
     
     ;3. DNS server runs outdated software versions with known vulnerabilities
     (outdated-dns-software ?DNSServer)
     
     ;4. DNS server is positioned within attacker's network reach
     (dns-attacker-network-reach ?DNSServer)
     
     ;5. DNS server lacks DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) encryption
     (not (dns-doh-enabled ?DNSServer))
     (not (dns-dot-enabled ?DNSServer))
     
     ;6. DNS server has insufficient rate limiting and behavioral analysis protections
     (dns-insufficient-rate-limiting ?DNSServer)
     
     ;7. DNS server uses predictable transaction ID generation algorithms
     (dns-predictable-transaction-ids ?DNSServer))
     
  :effect (and (vulnerable-dns-infrastructure ?DNSServer)
                (increase (total-cost) 21) ))

;;;#################################### Other application, attacker, user, infrastructure actions ####################################;;;
  (:action attacker-crafts-malicious-logback
    :parameters (?BenignFile - logback-config ?MaliciousFile - logback-config ?Application - application ?CVEID - cve-identifier)
    :precondition (and (legitimate-file ?BenignFile) 
                       (exposed-attack-surface ?Application ?CVEID)
                       (exploit-by ?CVEID change-to-malicious-logback-config))
    :effect (and (malicious-file ?MaliciousFile)
                 (has-janino-evaluator ?MaliciousFile) 
                 (contains-arbitrary-code ?MaliciousFile)
                 (increase (total-cost) 1)))
   
  (:action attacker-sends-malicious-file-via-commonication-channel 
    :parameters (?Application - application ?MaliciousFile - file ?MaliciousMessage - message ?Comchannel - comchannel ?CVEID - cve-identifier)
    :precondition (and (malicious-file ?MaliciousFile)
                       (exposed-attack-surface ?Application ?CVEID)
                       ; (has-janino-evaluator ?MaliciousFile)
                       ; (contains-arbitrary-code ?MaliciousFile)
                      )
    :effect (and (com-channel-msg ?Comchannel ?MaliciousMessage) 
                 (malicious-msg ?MaliciousMessage)
                 (message-has-file ?MaliciousMessage ?MaliciousFile) 
                 (message-sent ?MaliciousMessage)
                 (increase (total-cost) 1)))

  (:action user-receives-message
     :parameters (?User - user ?Message - message ?Comchannel - comchannel)
     :precondition (and (com-channel-msg ?Comchannel ?Message) 
                     (message-sent ?Message))
     :effect (and (message-received ?Message)
                (msg-reminder ?Message)
                (increase (total-cost) 1)))
 
  (:action user-starts-commonication-channel 
    :parameters (?User - user ?Comchannel - comchannel ?Message - message)
    :precondition (and (com-channel-msg ?Comchannel ?Message) 
                       (message-received ?Message)
                       (msg-reminder ?Message))
    :effect (and (user-use-communication-channel ?User ?Comchannel)
                 (running-communication-channel ?Comchannel)
                 (increase (total-cost) 22)))

  (:action user-reads-message
    :parameters (?User - user ?Comchannel - comchannel ?Message - message)
    :precondition (and (user-use-communication-channel ?User ?Comchannel) 
                       (running-communication-channel ?Comchannel)
                       (com-channel-msg ?Comchannel ?Message) )
    :effect (and (msg-opened ?Message)
                 (increase (total-cost) 11)))


  (:action user-downloads-malicious-file-in-message
    :parameters (?User - user ?MaliciousMessage - message ?MaliciousFile - file)
    :precondition (and (malicious-file ?MaliciousFile)
                       (malicious-msg ?MaliciousMessage)
                       ;(com-channel-msg ?Comchannel ?MaliciousMessage)
                       (message-has-file ?MaliciousMessage ?MaliciousFile) 
                       (msg-opened ?MaliciousMessage))
    :effect (and (downloaded ?MaliciousFile)
                 (increase (total-cost) 171)) ) 


  (:action user-navigates-to-config-dir
    :parameters (?User - user ?Directory - path ?File - file)
    :precondition (and (has-access ?User ?Directory) 
                       (downloaded ?File))
    :effect (and (in-directory ?User ?Directory)
                (increase (total-cost) 161)))


  (:action user-replaces-logback
    :parameters (?Application - application ?User - user ?MaliciousFile - logback-config ?LegitimateFile - logback-config ?Directory - path ?CVEID - cve-identifier)
    :precondition (and (exposed-attack-surface ?Application ?CVEID)
                       (exploit-by ?CVEID change-to-malicious-logback-config)
                      (malicious-file ?MaliciousFile)
                      (legitimate-file ?LegitimateFile)
                      (downloaded ?MaliciousFile)
                      (in-directory ?User ?Directory)
                      (has-write-access ?User ?Directory)
                      (located-at ?LegitimateFile ?Directory))
    :effect (and (not (located-at ?LegitimateFile ?Directory)) 
                (located-at ?MaliciousFile ?Directory) 
                (config-replaced ?MaliciousFile)
                (increase (total-cost) 1)))

  (:action user-starts-application
    :parameters (?User - user ?Application - application ?MaliciousFile - file)
    :precondition (and (config-replaced ?MaliciousFile))
    :effect (and (running-app ?Application)
                 (increase (total-cost) 1)))

  (:action application-loads-malicious-config-via-dir
    :parameters (?Application - application ?MaliciousFile - file ?Directory - path)
    :precondition (and (running-app ?Application)
                      (malicious-file ?MaliciousFile)
                      (has-config-dir ?Application ?Directory)
                      (located-at ?MaliciousFile ?Directory)
                      (config-replaced ?MaliciousFile))
    :effect (and (malicious-config-loaded-via-config-dir ?MaliciousFile ?Directory)
                  (malicious-config-loaded ?MaliciousFile)
                  (increase (total-cost) 1)))


  (:action application-executes-code
    :parameters (?Application - application ?MaliciousFile - file)
    :precondition (and (malicious-file ?MaliciousFile)
                      (has-janino-evaluator ?MaliciousFile)
                      (malicious-config-loaded ?MaliciousFile))
    :effect (and (elevation-of-privilege ?Application)
                 (increase (total-cost) 1)))

   (:action attacker-hosts-file-on-controlled-server
    :parameters (?Application - application ?MaliciousFile - file ?ControlledServer - controlled-server ?CVEID - cve-identifier)
    :precondition (and (exposed-attack-surface ?Application ?CVEID)
                      (malicious-file ?MaliciousFile)
                      (has-janino-evaluator ?MaliciousFile) 
                      (contains-arbitrary-code ?MaliciousFile))
    :effect (and (file-hosted-on-server ?MaliciousFile ?ControlledServer)
                  (increase (total-cost) 1)))
 
 (:action attacker-generates-url-to-file
    :parameters (?Application - application ?MaliciousFileUrl - file-url ?MaliciousFile - file ?ControlledServer - controlled-server ?CVEID - cve-identifier)
    :precondition (and (exposed-attack-surface ?Application ?CVEID)
                       (file-hosted-on-server ?MaliciousFile ?ControlledServer))
    :effect (and (url-points-to-file ?MaliciousFileUrl ?MaliciousFile)
                 (malicious-url ?MaliciousFileUrl)
                 (malicious-file-url ?MaliciousFileUrl)
                  (increase (total-cost) 1)))

 (:action attacker-sends-malicious-file-url-via-communication-channel  ;;this action should be commented out for AP 1.3
    :parameters (?Application - application ?FileUrl - file-url ?MaliciousMessage - message ?Comchannel - comchannel ?CVEID - cve-identifier)
    :precondition (and (exposed-attack-surface ?Application ?CVEID)
                        (malicious-file-url ?FileUrl))
    :effect (and (com-channel-msg ?Comchannel ?MaliciousMessage) 
                 (malicious-msg ?MaliciousMessage)
                (message-has-file-url ?MaliciousMessage ?FileUrl) 
                (message-sent ?MaliciousMessage)
                (increase (total-cost) 1)))

 ;; download the file by clicking
  (:action user-downloads-malicious-file-by-clicking-url-in-message
    :parameters (?User - user ?MaliciousMessage - message ?MalicousFileUrl - file-url ?MaliciousFile -file)
    :precondition (and (malicious-msg ?MaliciousMessage)
                      (malicious-file-url ?MalicousFileUrl)
                      (malicious-file ?MaliciousFile)
                      (msg-opened ?MaliciousMessage)
                      (message-has-file-url ?MaliciousMessage ?MalicousFileUrl) 
                      (url-points-to-file ?MalicousFileUrl ?MaliciousFile))
    :effect (and (downloaded ?MaliciousFile)
                 (file-url-accessed ?MalicousFileUrl)
                  (increase (total-cost) 171)))



  (:action attacker-forges-website
    :parameters (?Application - application ?Website - website ?ControlledServer - controlled-server ?CVEID - cve-identifier)
    :precondition (and (exposed-attack-surface ?Application CVE_2024_12798)) 
    :effect (and (website-hosted-on-server ?Website ?ControlledServer)
               (forged-website ?Website)
                (increase (total-cost) 1)))
 
  (:action attacker-includes-malicious-file-url-in-website   
    :parameters (?Application - application ?Website - website ?MaliciousFileUrl - file-url ?MaliciousFile - file ?CVEID - cve-identifier)
   :precondition (and  (exposed-attack-surface ?Application ?CVEID)
                       (forged-website ?Website)
                       (malicious-file-url ?MaliciousFileUrl)
                       (malicious-file ?MaliciousFile)
                       (url-points-to-file ?MaliciousFileUrl ?MaliciousFile)) 
    :effect (and (forged-website-contains-malicious-file-url ?Website ?MaliciousFileUrl)
                 (forged-website-contains-malicious-url ?Website ?MaliciousFileUrl)
                  (increase (total-cost) 1)))


(:action attacker-generates-forged-website-url
  :parameters (?Application - application ?WebsiteUrl - website-url ?Website - website ?ControlledServer - controlled-server ?MaliciousUrl -url ?CVEID - cve-identifier) 
  :precondition (and  (exposed-attack-surface ?Application ?CVEID)
                     (forged-website ?Website)
                     (malicious-url ?MaliciousUrl)
                     (website-hosted-on-server ?Website ?ControlledServer)
                     (forged-website-contains-malicious-url ?Website ?MaliciousUrl)) 
  :effect (and (url-points-to-forged-website ?WebsiteUrl ?Website)
               (malicious-url ?WebsiteUrl)
               (malicious-website-url ?WebsiteUrl)
                (increase (total-cost) 1)))


 (:action attacker-sends-forged-website-url-via-communication-channel 
    :parameters (?Application - application ?WebsiteUrl - website-url ?MaliciousMessage - message ?Comchannel - comchannel ?CVEID - cve-identifier)
    :precondition (and  (exposed-attack-surface ?Application ?CVEID)
                        (malicious-website-url ?WebsiteUrl))
    :effect (and (com-channel-msg ?Comchannel ?MaliciousMessage) 
                 (malicious-msg ?MaliciousMessage)
                (message-has-website-url ?MaliciousMessage ?WebsiteUrl) 
                (message-sent ?MaliciousMessage)
                (increase (total-cost) 1)))

 (:action user-clicks-mailicious-website-url-in-message
    :parameters (?User - user ?Comchannel - comchannel ?MaliciousMessage - message  ?MaliciousWebsiteUrl - website-url)
    :precondition (and (malicious-msg ?MaliciousMessage) 
                      (malicious-website-url ?MaliciousWebsiteUrl)
                      (user-use-communication-channel ?User ?Comchannel) 
                      (com-channel-msg ?Comchannel ?MaliciousMessage) 
                      (message-has-website-url ?MaliciousMessage ?MaliciousWebsiteUrl) 
                      (msg-opened ?MaliciousMessage))
    :effect (and (website-url-accessed ?MaliciousWebsiteUrl)
                 (increase (total-cost) 171)))

(:action user-visits-forged-website
  :parameters (?User - user ?WebsiteUrl  - website-url ?ForgedWebsite - website)
  :precondition (and (malicious-website-url ?WebsiteUrl)
                     (forged-website ?ForgedWebsite)
                     (url-points-to-forged-website ?WebsiteUrl ?ForgedWebsite)
                     (website-url-accessed ?WebsiteUrl))
  :effect (and (forged-website-visited-by-user ?ForgedWebsite ?User)
               (increase (total-cost) 1)))

(:action user-downloads-malicious-file-by-clicking-url-in-forged-website
  :parameters (?User - user ?ForgedWebsite - website ?MaliciousFileUrl - file-url ?MaliciousFile - file)
  :precondition (and (forged-website ?ForgedWebsite)          
                     (malicious-file-url ?MaliciousFileUrl)
                     (malicious-file ?MaliciousFile)
                     (forged-website-visited-by-user ?ForgedWebsite ?User)
                     (forged-website-contains-malicious-file-url ?ForgedWebsite ?MaliciousFileUrl)
                     (url-points-to-file ?MaliciousFileUrl ?MaliciousFile))
  :effect (and (file-url-accessed ?MaliciousFileUrl)
          (downloaded ?MaliciousFile)
           (increase (total-cost) 171)))

(:action attacker-creates-malicious-script-tampering-env-var-as-malicious-url
  :parameters (?Application - application ?MaliciousScript - script ?EnvVar - env-var ?MaliciousFileUrl - file-url ?CVEID - cve-identifier)
  :precondition (and  (exposed-attack-surface ?Application ?CVEID)
                      (exploit-by ?CVEID change-to-malicious-logback-config)
                     (env-var-logback-set-script ?MaliciousScript)
                     (malicious-file-url ?MaliciousFileUrl) )
  :effect (and (malicious-script ?MaliciousScript)
               (malicious-script-sets-env-var ?MaliciousScript ?EnvVar ?MaliciousFileUrl)
                (increase (total-cost) 1)))

(:action attacker-sends-malicious-script-via-communication-channel       
    :parameters (?Application - application ?MaliciousScript - script ?MaliciousMessage - message ?Comchannel - comchannel ?CVEID - cve-identifier)
    :precondition (and   (exposed-attack-surface ?Application ?CVEID)
                      (env-var-logback-set-script ?MaliciousScript)
                      (malicious-script ?MaliciousScript))
    :effect (and (com-channel-msg ?Comchannel ?MaliciousMessage)
        (malicious-msg ?MaliciousMessage)
        (message-has-malicious-script ?MaliciousMessage ?MaliciousScript)
        (message-sent ?MaliciousMessage)
        (increase (total-cost) 1)))

(:action user-opens-malicious-script-attachment-in-message
    :parameters (?Application - application ?User - user ?MaliciousMessage - message ?MaliciousScript - script ?Comchannel - comchannel)
    :precondition (and 
        (not (script-execution-prompt-enabled ?Application))
        (malicious-msg ?MaliciousMessage)
        (env-var-logback-set-script ?MaliciousScript)
        (malicious-script ?MaliciousScript)
        (com-channel-msg ?Comchannel ?MaliciousMessage)
        (message-has-malicious-script ?MaliciousMessage ?MaliciousScript)
        (msg-opened ?MaliciousMessage) ; Requires email to be opened first (from user-reads-email)
    )
    :effect (and (malicious-script-installed  ?MaliciousScript)
               (increase (total-cost) 171)))

(:action application-sets-env-var-via-malicious-script
    :parameters (?Application - application ?MaliciousScript - script ?EnvVar - env-var ?MaliciousFileUrl - file-url ?MaliciousFile - file ?CVEID - cve-identifier)
    :precondition (and (env-var-logback-set-script ?MaliciousScript)
        (exposed-attack-surface ?Application ?CVEID)
        (malicious-script ?MaliciousScript)
        (malicious-file ?MaliciousFile)
        (malicious-file-url ?MaliciousFileUrl)
        (malicious-script-installed ?MaliciousScript)
        (malicious-script-sets-env-var ?MaliciousScript ?EnvVar ?MaliciousFileUrl)
        (url-points-to-file ?MaliciousFileUrl ?MaliciousFile)   )
    :effect (and (env-var-set-by-malicious-url ?EnvVar ?MaliciousFileUrl)
            (config-replaced ?MaliciousFile)
             (increase (total-cost) 1)))

(:action user-downloads-malicious-script-in-message
    :parameters (?Application - application ?User - user ?MaliciousMessage - message ?MaliciousScript - script)
    :precondition (and (script-execution-prompt-enabled ?Application)
         (malicious-msg ?MaliciousMessage)
        (env-var-logback-set-script ?MaliciousScript)
        (malicious-script ?MaliciousScript)
        (message-has-malicious-script ?MaliciousMessage ?MaliciousScript)       
        (msg-opened ?MaliciousMessage))
    :effect (and (malicious-script-downloaded ?MaliciousScript)
                 (increase (total-cost) 171)) )

;; ===The way of activating mal-script's execution==
(:action user-double-click-download-script
 :parameters (?Application - application ?User - user ?MaliciousScript - script)
    :precondition (and  (script-execution-prompt-enabled ?Application)
                       (env-var-logback-set-script ?MaliciousScript)
                       (malicious-script ?MaliciousScript)
                       (malicious-script-downloaded ?MaliciousScript))
    :effect (and (malicious-script-execution-activated ?MaliciousScript)
                 (increase (total-cost) 1)))


(:action application-prompt-malicious-script-execution
    :parameters (?Application - application ?MaliciousScript - script)
    :precondition (and   (script-execution-prompt-enabled ?Application)
                       (env-var-logback-set-script ?MaliciousScript)
                       (malicious-script ?MaliciousScript)
                       (malicious-script-execution-activated ?MaliciousScript))
    :effect (and (malicious-script-execution-warning-active ?MaliciousScript)
                  (increase (total-cost) 1)))

(:action user-confirm-malicious-script-execution
    :parameters (?Application - application ?User -user ?MaliciousScript - script)
    :precondition (and  (script-execution-prompt-enabled ?Application)
        (env-var-logback-set-script ?MaliciousScript)
        (malicious-script ?MaliciousScript)
        (malicious-script-downloaded ?MaliciousScript)
        (malicious-script-execution-warning-active ?MaliciousScript))
    :effect (and (malicious-script-execution-confirmed ?MaliciousScript)
                  (increase (total-cost) 1)))

(:action application-sets-env-var-via-malicious-script
    :parameters (?Application - application ?MaliciousScript - script ?EnvVar - env-var ?MaliciousFileUrl - file-url ?MaliciousFile - file ?CVEID - cve-identifier)
    :precondition (and  (exposed-attack-surface ?Application ?CVEID)
        (env-var-logback-set-script ?MaliciousScript)
        (malicious-script ?MaliciousScript)
        (malicious-file ?MaliciousFile)
        (malicious-file-url ?MaliciousFileUrl)
        (malicious-script-execution-confirmed ?MaliciousScript)
        (malicious-script-sets-env-var ?MaliciousScript ?EnvVar ?MaliciousFileUrl)
        (url-points-to-file ?MaliciousFileUrl ?MaliciousFile) )
    :effect (and (env-var-set-by-malicious-url ?EnvVar ?MaliciousFileUrl)
            (config-replaced ?MaliciousFile)
             (increase (total-cost) 1)))


(:action application-loads-malicious-config-via-env-var
    :parameters (?Application - application ?EnvVar - env-var ?MaliciousFileUrl - file-url ?MaliciousFile - file ?CVEID - cve-identifier)
    :precondition (and 
        (exposed-attack-surface ?Application ?CVEID)
        (running-app ?Application)      
        (malicious-file ?MaliciousFile)
        (malicious-file-url ?MaliciousFileUrl)
        (env-var-set-by-malicious-url ?EnvVar ?MaliciousFileUrl)
        (url-points-to-file ?MaliciousFileUrl ?MaliciousFile)
        (has-janino-evaluator ?MaliciousFile)
        (contains-arbitrary-code ?MaliciousFile)
    )
    :effect (and (malicious-config-loaded-via-env-var ?MaliciousFile ?EnvVar)
                (malicious-config-loaded ?MaliciousFile)
                 (increase (total-cost) 1)) )


(:action attacker-hosts-malicious-script-on-controlled-server
  :parameters (?Application - application ?MaliciousScript - script ?ControlledServer - controlled-server ?CVEID - cve-identifier)
  :precondition (and  (exposed-attack-surface ?Application ?CVEID)
                      (env-var-logback-set-script ?MaliciousScript)
                     (malicious-script ?MaliciousScript))
  :effect (and (malicious-script-hosted-on-server ?MaliciousScript ?ControlledServer)
               (increase (total-cost) 1)))

(:action attacker-generates-download-url-to-script
  :parameters (?Application - application ?MalScriptUrl - script-url ?MaliciousScript - script ?ControlledServer - controlled-server ?CVEID - cve-identifier)
  :precondition (and (exposed-attack-surface ?Application ?CVEID)
                     (env-var-logback-set-script ?MaliciousScript)
                     (malicious-script ?MaliciousScript)
                     (malicious-script-hosted-on-server ?MaliciousScript ?ControlledServer))
  :effect (and (url-points-to-script ?MalScriptUrl ?MaliciousScript)
               (malicious-url ?MalScriptUrl)
               (malicious-script-url ?MalScriptUrl)
                (increase (total-cost) 1)))


(:action attacker-sends-malicious-script-url-via-commuication-channel   
  :parameters (?Application - application ?MaliciousMessage - message ?MalScriptUrl - script-url ?Comchannel - comchannel ?CVEID - cve-identifier)
  :precondition (and (exposed-attack-surface ?Application ?CVEID)
                (malicious-script-url ?MalScriptUrl))
  :effect (and (com-channel-msg ?Comchannel ?MaliciousMessage)
               (malicious-msg ?MaliciousMessage)
               (message-has-malicious-script-url ?MaliciousMessage ?MalScriptUrl)
               (message-sent ?MaliciousMessage)
                (increase (total-cost) 1)))

;; download the script by clicking
(:action user-downloads-malicious-script-by-clicking-url-in-message
  :parameters (?User - user ?MaliciousMessage - message ?MalScriptUrl - script-url ?MaliciousScript - script)
  :precondition (and (malicious-msg ?MaliciousMessage)          
                     (malicious-script-url ?MalScriptUrl)
                     (env-var-logback-set-script ?MaliciousScript)
                     (malicious-script ?MaliciousScript)
                     (message-has-malicious-script-url ?MaliciousMessage ?MalScriptUrl)
                     (msg-opened ?MaliciousMessage)
                     (url-points-to-script ?MalScriptUrl ?MaliciousScript))
  :effect (and (malicious-script-downloaded ?MaliciousScript)
           (script-url-accessed ?MalScriptUrl)
             (increase (total-cost) 171)))
 
  (:action attacker-includes-malicious-script-url-in-website
    :parameters ( ?Application - application ?Website - website ?MaliciousScriptUrl - Script-url ?MaliciousScript - script ?CVEID - cve-identifier)
    :precondition (and  (exposed-attack-surface ?Application ?CVEID)
                       (forged-website ?Website)     
                       (malicious-script-url ?MaliciousScriptUrl)
                       (env-var-logback-set-script ?MaliciousScript)
                       (malicious-script ?MaliciousScript)
                       (url-points-to-script ?MaliciousScriptUrl ?MaliciousScript)) 
    :effect (and (forged-website-contains-malicious-script-url ?Website ?MaliciousScriptUrl)
                (forged-website-contains-malicious-url ?Website ?MaliciousScriptUrl)
                  (increase (total-cost) 1)))

(:action user-downloads-malicious-script-by-clicking-url-in-forged-website
  :parameters (?User - user ?ForgedWebsite - website ?MaliciousScriptUrl - script-url ?MaliciousScript - script)
  :precondition (and (forged-website ?ForgedWebsite)
                     (malicious-script-url ?MaliciousScriptUrl)
                     (env-var-logback-set-script ?MaliciousScript)
                     (malicious-script ?MaliciousScript)
                     (forged-website-visited-by-user ?ForgedWebsite ?User)
                     (forged-website-contains-malicious-script-url ?ForgedWebsite ?MaliciousScriptUrl)
                     (url-points-to-script ?MaliciousScriptUrl ?MaliciousScript))
  :effect (and (script-url-accessed ?MaliciousScriptUrl)
          (malicious-script-downloaded ?MaliciousScript)
            (increase (total-cost) 171)))


(:action attacker-crafts-tls-flood-script
  :parameters (?Application - application ?MaliciousFloodScript - script ?Tomcat - tomcat ?CVEID - cve-identifier)
  :precondition (and  (exploit-by ?CVEID abuse-tls-handshake)
                     (tls-flood-script ?MaliciousFloodScript)
                     (exposed-attack-surface ?Application ?CVEID))      
  :effect (and (malicious-script ?MaliciousFloodScript)
               (malicious-tls-flood-script ?MaliciousFloodScript)
                 (increase (total-cost) 1)))

(:action attacker-initiates-tls-flood 
  :parameters (?Application - application ?MaliciousFloodScript - script ?Tomcat - tomcat ?TLSConnector - tls-connector ?CVEID - cve-identifier)
  :precondition (and  (tls-flood-script ?MaliciousFloodScript)
                     (malicious-script ?MaliciousFloodScript)
                     (malicious-tls-flood-script ?MaliciousFloodScript)
                     (exploit-by ?CVEID abuse-tls-handshake)
                     (exposed-attack-surface ?Application ?CVEID))
  :effect (and (tls-flood-active ?MaliciousFloodScript)
           (tls-handshake-request-sent ?MaliciousFloodScript)
           (increase (total-cost) 1)))


(:action application-keeps-allocate-resources-for-handshakes
  :parameters (?Tomcat - tomcat ?TLSConnector - tls-connector ?MaliciousFloodScript - script)
  :precondition (and  (tls-flood-script ?MaliciousFloodScript)
                     (malicious-script ?MaliciousFloodScript)
                     (malicious-tls-flood-script ?MaliciousFloodScript)
                     (tls-flood-active ?MaliciousFloodScript) 
                     (tls-handshake-request-sent ?MaliciousFloodScript)
                     (vulnerable-tomcat ?Tomcat))
  :effect (and (tls-handshake-request-received ?MaliciousFloodScript)
          (much-memory-allocated ?Tomcat)
          (increase (total-cost) 1)))

(:action application-triggers-outofmemory-error
  :parameters (?Tomcat - tomcat ?Application - application)
  :precondition (and  (much-memory-allocated ?Tomcat))
  :effect (and (memory-exhausted ?Application)
               (resource-exhausted ?Application)
               (out-of-memory-error ?Application)
                 (increase (total-cost) 1)))

(:action application-tomcat-crashes
  :parameters (?Application - application ?Tomcat - tomcat)
  :precondition ( and(memory-exhausted ?Application)
                     (much-memory-allocated ?Tomcat))
  :effect (and (denial-of-service ?Application)
              (increase (total-cost) 1))) 

(:action attacker-crafts-initial-tls-handshake-script
  :parameters (?Application - application ?MalTLSReScript - script ?Tomcat - tomcat ?CVEID - cve-identifier)
  :precondition (and (exploit-by ?CVEID abuse-tls-handshake)
             (exposed-attack-surface  ?Application ?CVEID )
             (tls-initial-handshake-request-script ?MalTLSReScript))
  :effect (and (malicious-script ?MalTLSReScript)
               (malicious-initial-tls-handshake-script ?MalTLSReScript)
                 (increase (total-cost) 1)))

(:action attacker-initial-tls-handshake
 :parameters (?Application - application ?MalTLSReScript - script ?CVEID - cve-identifier)
 :precondition (and (exploit-by ?CVEID abuse-tls-handshake)
                (exposed-attack-surface  ?Application ?CVEID ) 
                    (malicious-initial-tls-handshake-script ?MalTLSReScript))
 :effect (and (tls-handshake-request-sent ?MalTLSReScript)
              (increase (total-cost) 1)))

(:action application-allocates-initial-memory-for-tls-handshake-upon-request-receiving
  :parameters (?Tomcat - tomcat ?TLSConnector - tls-connector ?MalTLSReScript - script)
  :precondition (and  (tls-initial-handshake-request-script ?MalTLSReScript)
                     (malicious-script ?MalTLSReScript)
                     (malicious-initial-tls-handshake-script ?MalTLSReScript)
                     (tls-handshake-request-sent ?MalTLSReScript))
  :effect (and  (tls-handshake-request-received ?MalTLSReScript)
                (one-time-memory-allocated ?Tomcat)
                (increase (total-cost) 1)))

(:action attacker-completes-initial-tls-handshake  
  :parameters (?MalTLSReScript - script ?Tomcat - tomcat ?TLSConnector - tls-connector )
  :precondition (and (tls-initial-handshake-request-script ?MalTLSReScript)
                     (malicious-script ?MalTLSReScript)
                     (malicious-initial-tls-handshake-script ?MalTLSReScript)
                     (tls-handshake-request-received ?MalTLSReScript)
                     (one-time-memory-allocated ?Tomcat))
  :effect (and (initial-tls-handshake-completed ?Tomcat)
                 (increase (total-cost) 1)))

(:action attacker-crafts-tls-renegotiation-script-to-exploit
  :parameters (?Application - application ?MalRenegoScript - script ?Tomcat - tomcat  ?CVEID - cve-identifier)
  :precondition (and  (exploit-by ?CVEID abuse-tls-handshake)
                   (exposed-attack-surface  ?Application ?CVEID)
                 (tls-renegotiation-script ?MalRenegoScript)
                      (initial-tls-handshake-completed ?Tomcat))
  :effect (and (malicious-script ?MalRenegoScript)
               (malicious-tls-renegotiation-script ?MalRenegoScript)
                 (increase (total-cost) 1)))

(:action attacker-sends-tls-renegotiation-flood-to-exploit  
  :parameters (?Application - application ?MalRenegoScript - script ?Tomcat - tomcat  ?TLSConnector - tls-connector ?CVEID - cve-identifier)
  :precondition (and (exploit-by ?CVEID abuse-tls-handshake)
                     (exposed-attack-surface  ?Application ?CVEID)
                     (tls-renegotiation-script ?MalRenegoScript)
                     (malicious-script ?MalRenegoScript)
                     (malicious-tls-renegotiation-script ?MalRenegoScript)
                     (initial-tls-handshake-completed ?Tomcat))
  :effect (and (tls-renegotiation-flood-active ?MalRenegoScript)
                (increase (total-cost) 1)))

(:action application-keeps-allocate-renegotiation-memory  
  :parameters (?Tomcat - tomcat ?TLSConnector - tls-connector ?MalRenegoScript - script)
  :precondition (and 
                     (tls-renegotiation-script ?MalRenegoScript)
                     (malicious-script ?MalRenegoScript)
                     (tls-renegotiation-flood-active ?MalRenegoScript) 
                     (one-time-memory-allocated ?Tomcat))  ; Requires initial allocation
  :effect (and (much-memory-allocated ?Tomcat)
               (increase (total-cost) 1)) )


(:action attacker-forge-phishing-website-minic-legitimate-app
    :parameters (?Application - application ?PhishingSite - website  ?ControlledServer - controlled-server ?CVEID - cve-identifier)
    :precondition (and (exposed-attack-surface ?Application ?CVEID)
                   (exploit-by ?CVEID build-phishingsite) )
    :effect (and  (forged-website ?PhishingSite)
                 (website-hosted-on-server ?PhishingSite ?ControlledServer)
                 (website-mimics-legitimate-app ?PhishingSite ?Application)
                   (increase (total-cost) 1)))


(:action attacker-generates-phishing-website-url
    :parameters (?Application - application ?PhishingSite - website ?ControlledServer - controlled-server ?PhishingURL - phishing-url ?CVEID - cve-identifier)
    :precondition (and (exposed-attack-surface ?Application ?CVEID)
                       (exploit-by ?CVEID build-phishingsite)
                       (forged-website ?PhishingSite)
                       (website-hosted-on-server ?PhishingSite ?ControlledServer))
    :effect (and (phishing-url-points-to-forge-website ?PhishingURL ?PhishingSite)
            (malicious-url ?PhishingURL)
            (malicious-phishing-site-url ?PhishingURL)
              (increase (total-cost) 1)))


(:action attacker-crafts-malicious-redirect-url-point-to-phishingsite 
    :parameters (?Application - application ?MaliciousURL - redirect-url ?PhishingURL - phishing-url ?PhishingSite - website ?Payload - payload-string ?CVEID - cve-identifier)
    :precondition (and (exposed-attack-surface ?Application ?CVEID)
                       (exploit-by ?CVEID build-phishingsite)
                       (exploit-by ?CVEID crafts-redirect-url-to-phishing-site)
                       (phishing-url-points-to-forge-website ?PhishingURL ?PhishingSite)
                       (forged-website ?PhishingSite))
    :effect (and (malicious-redirect-url ?MaliciousURL)
                 (malicious-url ?MaliciousURL)
                 (URL-contains-payload ?MaliciousURL ?Payload)
                 (payload-has-validation-bypass-capability ?Payload)
                 (redirects-to-phishing-URL ?MaliciousURL ?PhishingURL)
                 (vulnerable-redirect-URL-created ?MaliciousURL)
                   (increase (total-cost) 1)))


(:action attacker-sends-malicious-redirect-url-via-communication-channel
    :parameters (?MaliciousURL - redirect-url ?Message - message ?Channel - comchannel ?Payload - payload-string ?CVEID - cve-identifier)
    :precondition (and (exploit-by ?CVEID crafts-redirect-url)
                     (malicious-redirect-url ?MaliciousURL)
                      (URL-contains-payload ?MaliciousURL ?Payload))
    :effect (and (com-channel-msg ?Channel ?Message)
                 (malicious-msg ?Message)
                 (message-has-redirect-url ?Message ?MaliciousURL)
                 (message-sent ?Message)
                   (increase (total-cost) 1)))
  

(:action user-clicks-malicious-redirect-url-in-message 
    :parameters (?User - user ?Browser - browser ?Comchannel - comchannel ?MaliciousMessage - message ?RedirectUrl - redirect-url ?PhishingURL - phishing-url)
    :precondition (and 
                  (malicious-msg ?MaliciousMessage) 
                  (malicious-redirect-url ?RedirectUrl)
                  (user-use-communication-channel ?User ?Comchannel) 
                  (com-channel-msg ?Comchannel ?MaliciousMessage) 
                  (message-has-redirect-url ?MaliciousMessage ?RedirectUrl) 
                  (msg-opened ?MaliciousMessage)
                  (redirects-to-phishing-URL ?RedirectUrl ?PhishingURL)
                  (is-default-browser ?Browser))
    :effect (and (redirect-url-clicked ?RedirectUrl) 
                 (malicious-url-clicked ?RedirectUrl)
                 (http-request-triggered ?RedirectUrl)
                 (running-browser ?Browser)
                 (user-use-browser ?User ?Browser) 
                   (increase (total-cost) 171))) 


(:action attacker-publishes-redirect-url-social-media
    :parameters (?RedirectURL - redirect-url ?PhishingURL - phishing-url ?SocialMedia - social-media ?Payload - payload-string ?CVEID - cve-identifier) 
    :precondition (and (exploit-by ?CVEID crafts-redirect-url)
                        (malicious-url ?RedirectURL)
                       (URL-contains-payload ?RedirectURL ?Payload) 
                       (redirects-to-phishing-URL ?RedirectURL ?PhishingURL))
    :effect (and (redirect-url-published-on-social-media ?RedirectURL ?SocialMedia)
                 (redirect-url-visible ?RedirectURL ?SocialMedia)
                 (malicious-url-published-on-social-media ?RedirectURL ?SocialMedia)
                 (malicious-url-visible ?RedirectURL ?SocialMedia)
                 (increase (total-cost) 1)))

(:action user-scrolls-social-media
    :parameters (?User - user ?SocialMedia - social-media ?MaliciousURL - url)
    :precondition (and (malicious-url-published-on-social-media ?MaliciousURL ?SocialMedia)
                       (malicious-url-visible ?MaliciousURL ?SocialMedia))
    :effect (and (running-social-media ?SocialMedia)
                 (user-scrolling-social-media ?User ?SocialMedia)
                 (increase (total-cost) 22)))

(:action user-notices-malicious-url
    :parameters (?User - user ?SocialMedia - social-media ?MaliciousURL - url)
    :precondition (and (malicious-url ?MaliciousURL)
                       (running-social-media ?SocialMedia)
                       (user-scrolling-social-media ?User ?SocialMedia)
                       (malicious-url-visible ?MaliciousURL ?SocialMedia))
    :effect (and (malicious-url-noticed ?MaliciousURL ?User)
             (increase (total-cost) 365)))

(:action user-clicks-malicious-url-in-social-media
    :parameters (?User - user ?MaliciousURL - url  ?SocialMedia - platform ?Browser - browser)
    :precondition (and  (malicious-url ?MaliciousURL)
                        (malicious-url-published-on-social-media ?MaliciousURL ?SocialMedia)
                        (malicious-url-noticed ?MaliciousURL ?User)
                        (is-default-browser ?Browser) )
    :effect (and (malicious-url-clicked ?MaliciousURL)
                 (http-request-triggered ?MaliciousURL)
                 (running-browser ?Browser)
                 (user-use-browser ?User ?Browser) 
                   (increase (total-cost) 171) )) 

(:action user-browser-sends-http-get-request-to-application
    :parameters (?User - user ?HttpGetRequest - http-get-request ?RedirectUrl - redirect-url ?Browser - browser)
    :precondition (and (malicious-url-clicked ?RedirectUrl) 
                        (user-use-browser ?User ?Browser)
                         (running-browser ?Browser))
    :effect (and (http-get-request-sent ?HttpGetRequest)
                 (HTTP-request-includes-redirect-url ?RedirectUrl)
                 (increase (total-cost) 1) ))
                  

(:action application-processes-http-get-request-by-parser
    :parameters (?HttpGetRequest - http-get-request ?RedirectUrl - redirect-url ?Application - application ?Parser - url-parser)
    :precondition (and (http-get-request-received ?HttpGetRequest ?Application)
                       (HTTP-request-includes-redirect-url ?RedirectUrl)
                       (or  (exposed-attack-surface ?Application CVE_2024_22243)
                            (exposed-attack-surface ?Application CVE_2024_22259)
                             (exposed-attack-surface ?Application CVE_2024_22262))
                       (has-dependency-on-vulnerable-paser ?Application ?Parser))
    :effect (and (running-Parser ?Parser)
                (increase (total-cost) 1)))

(:action application-vulnerably-validates-host-in-URL
    :parameters (?Application - application ?RedirectUrl - redirect-url ?Parser - url-parser)
    :precondition (and (running-Parser ?Parser)
                       (or  (exposed-attack-surface ?Application CVE_2024_22243)
                            (exposed-attack-surface ?Application CVE_2024_22259)
                             (exposed-attack-surface ?Application CVE_2024_22262))
                       )
    :effect (and (URL-host-validation-passed ?RedirectUrl)
                   (increase (total-cost) 1)))

(:action application-server-sends-302-redirect-to-user-browser
    :parameters (?HttpGetRequest - http-get-request ?RedirectUrl - redirect-url ?PhishingUrl - phishing-url ?PhishingSite - website ?ControlledServer - controlled-server )
    :precondition (and 
                  (http-get-request-sent ?HttpGetRequest)
                  (HTTP-request-includes-redirect-url ?RedirectUrl)
                  (URL-host-validation-passed ?RedirectUrl)
                  (redirects-to-phishing-URL ?RedirectUrl ?PhishingUrl)
                  (phishing-url-points-to-forge-website ?PhishingUrl ?PhishingSite)
                  (website-hosted-on-server ?PhishingSite ?ControlledServer))
    :effect (and 
            (redirect-response-sent ?PhishingUrl)
              (increase (total-cost) 1))) 

(:action user-browser-follows-redirect
    :parameters (?User - user ?Browser - browser ?PhishingURL - phishing-url)
    :precondition (and (user-use-browser ?User ?Browser)
                   (redirect-response-sent ?PhishingURL))
    :effect (and (request-sent-to-phishing ?PhishingURL)
                   (increase (total-cost) 1)))

(:action attacker-serves-mimic-website
    :parameters (?PhishingURL - phishing-url ?Phishingsite - website  ?ControlledServer - controlled-server ?CVEID - cve-identifier)
    :precondition (and (request-sent-to-phishing ?PhishingURL)
                       (website-hosted-on-server ?PhishingSite ?ControlledServer)
                       (exploit-by ?CVEID build-phishingsite))
    :effect (and (mimic-response-sent ?PhishingURL)
                 (increase (total-cost) 1)))

(:action user-visits-phishing-site
    :parameters (?User - user ?PhishingURL - phishing-url ?Phishingsite - website)
    :precondition (and (mimic-response-sent ?PhishingURL)
                       (phishing-url-points-to-forge-website ?PhishingURL ?Phishingsite) )
    :effect (and (user-viewing-phishing-website ?User ?Phishingsite)
                   (increase (total-cost) 1)))

(:action user-enters-credentials
    :parameters (?User - user ?Credentials - credential ?Phishingsite - website ?Application - application)
    :precondition (and (user-viewing-phishing-website ?User ?Phishingsite)
                       (user-has-valid-credentials-application ?User ?Credentials ?Application))
    :effect (and (credentials-entered-to-phishingsite ?Credentials ?PhishingSite)
                  (increase (total-cost) 530)))

(:action attacker-phishing-website-submits-user-credentials
    :parameters (?Credentials - credential ?PhishingSite - website ?ControlledServer - controlled-server ?CVEID - cve-identifier)
    :precondition (and (credentials-entered-to-phishingsite ?Credentials ?PhishingSite)
                   (website-hosted-on-server ?PhishingSite ?ControlledServer)
                   (exploit-by ?CVEID build-phishingsite ))
    :effect (and (credentials-submitted-on-phishingsite ?Credentials ?PhishingSite)
                  (increase (total-cost) 1) ))

(:action attacker-intercepts-credentials-of-target-application
    :parameters (?Application - application ?Credentials - credential ?PhishingSite - website ?ControlledServer - controlled-server)
    :precondition (and (credentials-submitted-on-phishingsite ?Credentials ?PhishingSite)
                      (website-hosted-on-server ?PhishingSite ?ControlledServer))
    :effect (and (information-obtained ?Credentials)
                  (information-disclosure ?Application)
                  (increase (total-cost) 1)))

(:action attacker-uses-user-credentials-login-target-application 
    :parameters (?User - user ?Credentials - credential ?TargetApp - application)
    :precondition (and (user-has-valid-credentials-application ?User ?Credentials ?TargetApp)
                       (information-obtained ?Credentials))
    :effect (and (spoofing ?TargetApp)
                   (increase (total-cost) 1)))   

(:action attacker-crafts-malicious-redirect-url-point-to-internal-resource 
    :parameters (?MaliciousURL - redirect-url ?Payload - payload-string 
                  ?InternalResourceAddress - internal-address ?Application - application ?CVEID - cve-identifier)
    :precondition (and 
        (exposed-attack-surface ?Application ?CVEID)
        (exploit-by ?CVEID crafts-redirect-url))
    :effect (and 
        (malicious-redirect-url ?MaliciousURL)
        (malicious-url ?MaliciousURL)
        (URL-contains-payload ?MaliciousURL ?Payload)
        (payload-has-validation-bypass-capability ?Payload)
        (redirects-to-internal-resource ?MaliciousURL ?InternalResourceAddress)
        (vulnerable-redirect-URL-created ?MaliciousURL)
          (increase (total-cost) 1)))

(:action attacker-clicks-malicious-url-includes-internal-resources-request-pyload
   :parameters (?Browser - browser ?MaliciousURL - redirect-url ?InternalResourceAddress - internal-address)
   :precondition (and (malicious-redirect-url ?MaliciousURL)
                      (redirects-to-internal-resource ?MaliciousURL ?InternalResourceAddress)
                      (is-default-browser ?Browser))
   :effect (and (malicious-url-clicked ?MaliciousURL)
                (malicious-redirect-url-clicked ?MaliciousURL)
                (running-browser ?Browser)
                  (increase (total-cost) 1)))


(:action attacker-browser-sends-malicious-http-get-request-for-internal-resources
    :parameters (?Browser - browser ?HttpGetRequest - http-get-request ?MaliciousURL - redirect-url ?InternalResourceAddress - internal-address )
    :precondition (and 
        (running-browser ?Browser)
        (malicious-redirect-url ?MaliciousURL)
        (malicious-redirect-url-clicked ?MaliciousURL)
        (redirects-to-internal-resource ?MaliciousURL ?InternalResourceAddress))
    :effect (and (http-get-request-sent ?HttpGetRequest)
                 (HTTP-request-includes-redirect-url ?MaliciousURL)
                   (increase (total-cost) 1)))


(:action application-server-sends-internal-request
    :parameters (?RedirectUrl - redirect-url ?InternalResourceAddress - internal-address 
                  ?Application - application)
    :precondition (and 
        (HTTP-request-includes-redirect-url ?RedirectUrl)
        (redirects-to-internal-resource ?RedirectUrl ?InternalResourceAddress)
         (or  (exposed-attack-surface ?Application CVE_2024_22243)
              (exposed-attack-surface ?Application CVE_2024_22259)
              (exposed-attack-surface ?Application CVE_2024_22262))
        (URL-host-validation-passed ?RedirectUrl))
    :effect (and (internal-request-sent ?InternalResourceAddress)
                 (increase (total-cost) 1)))

(:action application-internal-server-responds-sensitive-information
    :parameters (?InternalResourceAddress - internal-address ?Data - sensitive-information ?Application - application)
    :precondition (and (internal-request-sent ?InternalResourceAddress)
                       (data-saved-in-internal-address ?Data ?InternalResourceAddress))
    :effect (and  (sensitive-information-located-internal-address ?Data ?InternalResourceAddress)
                  (sensitive-data-prepared-by-application ?Application ?Data)
                    (increase (total-cost) 1)))

(:action attacker-registers-account-on-target-application
    :parameters (?Account - account ?Application - application ?SessionCookie - session-cookie ?CVEID - cve-identifier)
    :precondition (and (exposed-attack-surface ?Application ?CVEID)
                       (exploit-by ?CVEID acquire-user-account)) 
    :effect (and (account-registered ?Account ?Application)
                 (attacker-has-account ?Account)
                 (session-cookie-obtained ?SessionCookie ?Account)
                 (account-has-normal-privileges ?Account)
                  (increase (total-cost) 1)))


(:action attacker-crafts-malicious-url-with-locale-bypass
    :parameters (?LocaleBypassURL - locale-bypass-url ?Application - application ?LocaleBypassParam - locale-bypass-parameter ?Account - account ?CVEID - cve-identifier)
    :precondition (and (exposed-attack-surface ?Application ?CVEID)
                       (exploit-by ?CVEID bypass-locale-specific-capitalization)
                       (has-locale-specific-exceptions ?Application)
                       (has-vulnerable-locale-transformation ?Application)
                       (attacker-has-account ?Account)
                       (account-has-normal-privileges ?Account))
    :effect (and (malicious-locale-bypass-url ?LocaleBypassURL)
                 (malicious-url ?LocaleBypassURL)
                 (url-contains-locale-bypass-parameter ?LocaleBypassURL ?LocaleBypassParam)
                 (parameter-uses-non-standard-capitalization ?LocaleBypassParam)
                 (parameter-targets-admin-field ?LocaleBypassParam)
                 (bypass-parameter-created ?LocaleBypassParam)
                   (increase (total-cost) 1)))


(:action attacker-clicks-malicious-url-includes-locale-bypass-pyload
    :parameters (?Browser - browser ?LocaleBypassURL - locale-bypass-url ?LocaleBypassParam - locale-bypass-parameter)
    :precondition (and (malicious-locale-bypass-url ?LocaleBypassURL)
                       (url-contains-locale-bypass-parameter ?LocaleBypassURL ?LocaleBypassParam)
                       (is-default-browser ?Browser))
    :effect (and (malicious-url-clicked ?LocaleBypassURL)
                 (http-get-request-triggered ?LocaleBypassURL)
                 (running-browser ?Browser)
                   (increase (total-cost) 1)))

(:action attacker-browser-sends-malicious-http-get-request-with-locale-bypass-pyload
    :parameters (?HttpGetRequest - http-get-request ?MaliciousURL - locale-bypass-url ?Browser - browser ?LocaleBypassParam - locale-bypass-parameter)
    :precondition (and (malicious-url-clicked ?MaliciousURL)
                       (http-get-request-triggered ?MaliciousURL)
                       (running-browser ?Browser)
                       (url-contains-locale-bypass-parameter ?MaliciousURL ?LocaleBypassParam))
    :effect (and (http-get-request-sent ?HttpGetRequest)
                 (request-contains-locale-bypass-param ?MaliciousURL ?LocaleBypassParam)
                   (increase (total-cost) 1)))

(:action application-server-invokes-databinder-with-locale-transformation
    :parameters (?Application - application ?HttpGetRequest - http-get-request ?MaliciousURL - locale-bypass-url ?LocaleBypassParam - locale-bypass-parameter ?DataBinder - data-binder ?TransformedParam - transformed-parameter ?CVEID - cve-identifier)
    :precondition (and (http-get-request-received ?HttpGetRequest ?Application)
                       (request-contains-locale-bypass-param ?MaliciousURL ?LocaleBypassParam)
                       (exposed-attack-surface ?Application ?CVEID)
                       (exploit-by ?CVEID bypass-locale-specific-capitalization)
                       (has-vulnerable-databinder ?Application ?DataBinder))
    :effect (and (databinder-invoked ?DataBinder ?LocaleBypassParam)
                 (parameter-transformed-to-lowercase ?LocaleBypassParam ?TransformedParam)
                 (non-standard-lowercase-created ?TransformedParam)
                   (increase (total-cost) 1)))

(:action application-databinder-fails-to-match-disallowed-fields-pattern
    :parameters (?Application - application ?DataBinder - data-binder ?LocaleBypassParam - locale-bypass-parameter ?TransformedParam - transformed-parameter ?DisallowedPattern - disallowed-pattern)
    :precondition (and (databinder-invoked ?DataBinder ?LocaleBypassParam)
                       (parameter-transformed-to-lowercase ?LocaleBypassParam ?TransformedParam)
                       (non-standard-lowercase-created ?TransformedParam)
                       ;(transformed-parameter-name ?TransformedParam)
                       (has-disallowed-databinder-fields-configuration ?Application))
    :effect (and (pattern-matching-failed ?TransformedParam ?DisallowedPattern)
                 (filter-bypassed ?TransformedParam)
                 (parameter-allowed-to-continue-binding ?TransformedParam)
                 (validation-bypass-successful ?TransformedParam)
                   (increase (total-cost) 1)))

(:action application-server-sets-admin-field-for-attacker
    :parameters (?Application - application ?Account - account ?TransformedParam - transformed-parameter)
    :precondition (and (parameter-allowed-to-continue-binding ?TransformedParam)
                       (validation-bypass-successful ?TransformedParam)
                       (attacker-has-account ?Account)
                       (account-has-normal-privileges ?Account)
                       (account-registered ?Account ?Application))
    :effect (and (admin-field-set-to-true ?Account)
                 (account-has-admin-privilege ?Account)
                 (tampering ?Application)
                 (elevation-of-privilege ?Application)
                   (increase (total-cost) 1)))

(:action attacker-crafts-http-flood-script
  :parameters (?Application - application ?MaliciousFloodScript - script ?SpringBoot - spring-boot ?CVEID - cve-identifier)
  :precondition (and  (http-flood-script ?MaliciousFloodScript)
                     (exposed-attack-surface  ?Application ?CVEID)
                      (exploit-by ?CVEID craft-http-flood-script))      
  :effect (and (malicious-script ?MaliciousFloodScript)
               (malicious-http-flood-script ?MaliciousFloodScript)
                 (increase (total-cost) 1)))

(:action attacker-initiates-http-flood
  :parameters (?Application - application ?MaliciousFloodScript - script ?SpringBoot - spring-boot ?CVEID - cve-identifier)
  :precondition (and  (http-flood-script ?MaliciousFloodScript)
                     (malicious-script ?MaliciousFloodScript)
                     (malicious-http-flood-script ?MaliciousFloodScript)
                     (exposed-attack-surface  ?Application ?CVEID))
  :effect (and (http-flood-active ?MaliciousFloodScript)
           (http-requests-sent ?MaliciousFloodScript)
             (increase (total-cost) 1)))

(:action application-processes-http-requests-without-limits
  :parameters (?SpringBoot - spring-boot ?MaliciousFloodScript - script)
  :precondition (and  (http-flood-script ?MaliciousFloodScript)
                     (malicious-script ?MaliciousFloodScript)
                     (malicious-http-flood-script ?MaliciousFloodScript)
                     (http-flood-active ?MaliciousFloodScript) 
                     (http-requests-sent ?MaliciousFloodScript) )
  :effect (and (http-requests-received ?MaliciousFloodScript)
          (much-memory-allocated ?SpringBoot)
            (increase (total-cost) 1)))

(:action application-exhausts-server-memory-resources
  :parameters (?Application - application ?SpringBoot - spring-boot)
  :precondition (and  (much-memory-allocated ?SpringBoot))
  :effect (and (memory-exhausted ?Application)
               (resource-exhausted ?Application)
               (application-unresponsive ?Application)
               (denial-of-service ?Application)
                 (increase (total-cost) 1)))

(:action application-becomes-unresponsive
  :parameters (?Application - application)
  :precondition (and (resource-exhausted ?Application))
  :effect (and (application-unresponsive ?Application)
               (denial-of-service ?Application)
                 (increase (total-cost) 1)))  
                 

(:action attacker-sets-up-malicious-server-with-domain
 :parameters (?Application - application  ?DNSServer - dns-server ?ControlledServer - controlled-server ?ControlledDomain - controlled-domain ?CVEID - cve-identifier)
 :precondition (and (exposed-attack-surface ?Application ?CVEID)
              (exploit-by ?CVEID sets-up-malicious-server)
              (vulnerable-dns-infrastructure ?DNSServer))
 :effect (and (malicious-server-setup-with-domain ?ControlledServer ?ControlledDomain)
              (increase (total-cost) 1)))

(:action attacker-obtains-valid-ssl-certificate-for-server
 :parameters (?ControlledServer - controlled-server ?SSLCertificate - ssl-certificate ?ControlledDomain -controlled-domain)
 :precondition (and (malicious-server-setup-with-domain ?ControlledServer ?ControlledDomain) )
 :effect (and (valid-ssl-certificate ?SSLCertificate ?ControlledDomain)
         (attacker-has-certificate ?SSLCertificate)
         (increase (total-cost) 1)))


(:action attacker-configures-server-with-certificate
 :parameters (?ControlledServer - controlled-server ?SSLCertificate - ssl-certificate ?ControlledDomain - controlled-domain)
 :precondition (and (malicious-server-setup-with-domain ?ControlledServer ?ControlledDomain)
                   (valid-ssl-certificate ?SSLCertificate ?ControlledDomain)
                   (attacker-has-certificate ?SSLCertificate))
 :effect (and (server-configured-with-certificate ?ControlledServer ?SSLCertificate)
         (malicious-server-ready ?ControlledServer)
          (increase (total-cost) 1)))


(:action attacker-performs-dns-poisoning
 :parameters (?DNSServer - dns-server ?LegitimateServer - legitimate-server ?ControlledServer - controlled-server ?LegitimateAddress - legitimate-ip-address ?MaliciousAddress - malicious-ip-address ?CVEID - cve-identifier)
 :precondition (and (exploit-by ?CVEID perform-dns-poisoning)
                   (vulnerable-dns-infrastructure ?DNSServer)
                   (legitimate-server-ip-address ?LegitimateServer ?LegitimateAddress)
                   (malicious-server-ready ?ControlledServer)
                   ;(attacker-controlled-server ?ControlledServer)
                   (controlled-server-ip-address ?ControlledServer ?MaliciousAddress))
 :effect (and (dns-poisoned ?DNSServer ?LegitimateServer ?MaliciousAddress)
         (forged-dns-records ?DNSServer ?LegitimateServer ?MaliciousAddress)
           (increase (total-cost) 1)))

(:action user-launches-target-application
 :parameters (?User - user ?Application - application ?CVEID - cve-identifier ?DNSServer - dns-server ?LegitimateServer - legitimate-server ?MaliciousAddress - malicious-ip-address)
 :precondition (and (exposed-attack-surface ?Application ?CVEID)
                  (dns-poisoned ?DNSServer ?LegitimateServer ?MaliciousAddress)
               (forged-dns-records ?DNSServer ?LegitimateServer ?MaliciousAddress))
 :effect (and (application-launched ?User ?Application)
         (user-session-active ?User ?Application)
           (increase (total-cost) 11)))

(:action user-initiates-connection-to-legitimate-domain
 :parameters (?User - user ?Application - application ?LegitimateServer - legitimate-server ?LegitimateAddress - legitimate-ip-address)
 :precondition (and  (application-launched ?User ?Application)
                   (user-session-active ?User ?Application)
                   (legitimate-server-ip-address ?LegitimateServer ?LegitimateAddress))
 :effect (and (connection-initiated ?User ?Application ?LegitimateServer)
         (connection-request-pending ?Application ?LegitimateServer)
           (increase (total-cost) 1)))

(:action application-performs-dns-lookup
 :parameters (?Application - application ?LegitimateServer - legitimate-server ?DNSServer - dns-server)
 :precondition (and (connection-request-pending ?Application ?LegitimateServer)
                   (https-connections-trigger-dns-resolution ?Application))
 :effect (and (dns-lookup-performed ?Application ?LegitimateServer)
         (dns-query-sent ?Application ?DNSServer ?LegitimateServer)
           (increase (total-cost) 1)))

(:action poisoned-dns-infrastructure-returns-attacker-server-ip
 :parameters (?Application - application ?DNSServer - dns-server ?LegitimateServer - legitimate-server ?MaliciousAddress - malicious-ip-address)
 :precondition (and 
                   (dns-query-sent ?Application ?DNSServer ?LegitimateServer)
                   (dns-poisoned ?DNSServer ?LegitimateServer ?MaliciousAddress)
                   (forged-dns-records ?DNSServer ?LegitimateServer ?MaliciousAddress))
 :effect (and (dns-response-returned ?DNSServer ?LegitimateServer ?MaliciousAddress)
         (ip-address-resolved ?LegitimateServer ?MaliciousAddress)
           (increase (total-cost) 1)))

(:action application-initiates-ssl-handshake-to-attacker-without-hostname
 :parameters (?Application - application ?ControlledServer - controlled-server ?LegitimateServer - legitimate-server ?MaliciousAddress - malicious-ip-address ?SSLSocket - ssl-socket)
 :precondition (and   (ip-address-resolved ?LegitimateServer ?MaliciousAddress)
                   (malicious-server-ready ?ControlledServer)
                   (controlled-server-ip-address ?ControlledServer ?MaliciousAddress))
 :effect (and (ssl-socket-created ?Application ?SSLSocket)
         (connection-request-to-attacker-server ?Application ?ControlledServer)
          (hostname-parameter-missing ?SSLSocket)
            (increase (total-cost) 1) ))

(:action attacker-server-presents-ssl-certificate
 :parameters (?Application - application ?ControlledServer - controlled-server ?SSLCertificate - ssl-certificate ?ControlledDomain - controlled-domain)
 :precondition (and (connection-request-to-attacker-server ?Application ?ControlledServer)
                   (server-configured-with-certificate ?ControlledServer ?SSLCertificate)
                   (valid-ssl-certificate ?SSLCertificate ?ControlledDomain))
 :effect (and (ssl-certificate-presented ?ControlledServer ?SSLCertificate)
         (certificate-verification-pending ?SSLCertificate)
           (increase (total-cost) 1)))

(:action application-bcjsse-performs-incorrect-hostname-verification
 :parameters (?Application - application ?BCJSSE - bcjsse ?LegitimateServer - legitimate-server ?ControlledServer - controlled-server ?SSLCertificate - ssl-certificate ?SSLSocket - ssl-socket ?MaliciousAddress - malicious-ip-address)
 :precondition (and (vulnerable-bcjsse ?Application ?BCJSSE)
                   (ssl-certificate-presented ?ControlledServer ?SSLCertificate)
                   (certificate-verification-pending ?SSLCertificate)
                   (hostname-parameter-missing ?SSLSocket)
                   (ip-address-resolved ?LegitimateServer ?MaliciousAddress))
 :effect (and (hostname-verification-bypassed ?Application ?BCJSSE)
         (connection-trusted-incorrectly ?Application)
         (certificate-validation-passed-incorrectly ?SSLCertificate)
           (increase (total-cost) 1)))

(:action application-establishes-ssl-connection-to-attacker-server
 :parameters (?Application - application ?ControlledServer - controlled-server ?LegitimateServer - legitimate-server ?MaliciousAddress - malicious-ip-address ?SSLSocket - ssl-socket)
 :precondition (and  (connection-trusted-incorrectly ?Application)
                     (ip-address-resolved ?LegitimateServer ?MaliciousAddress)
                     (malicious-server-ready ?ControlledServer)
                     (controlled-server-ip-address ?ControlledServer ?MaliciousAddress))
 :effect (and (ssl-connection-established ?Application ?ControlledServer)
             (connected-to-attacker-server ?Application ?ControlledServer) 
               (increase (total-cost) 1)))

(:action user-inputs-sensitive-information-in-the-webpage
 :parameters (?User - user ?Application - application ?ControlledServer - controlled-server ?SensitiveData - sensitive-information)
 :precondition (and (user-session-active ?User ?Application)
                    (connected-to-attacker-server ?Application ?ControlledServer)
                   (connection-trusted-incorrectly ?Application))
 :effect (and (sensitive-information-inputted ?User ?SensitiveData)
         (data-ready-for-transmission ?Application ?SensitiveData)
           (increase (total-cost) 530)))

(:action application-transmits-sensitive-information-to-attacker
 :parameters (?Application - application ?ControlledServer - controlled-server ?SensitiveData - sensitive-information)
 :precondition (and (connected-to-attacker-server ?Application ?ControlledServer)
                   (data-ready-for-transmission ?Application ?SensitiveData)
                   (connection-trusted-incorrectly ?Application))
 :effect (and (sensitive-information-transmitted ?Application ?SensitiveData)
         (sensitive-data-sent-to-attacker ?SensitiveData)
           (increase (total-cost) 1)))

(:action attacker-captures-sensitive-information-of-target-application  
 :parameters (?Application - application ?SensitiveData - sensitive-information  ?CVEID - cve-identifier)
 :precondition (and (exposed-attack-surface ?Application ?CVEID)
                   (sensitive-data-sent-to-attacker ?SensitiveData)
                   (sensitive-information-transmitted ?Application ?SensitiveData))
 :effect (and (sensitive-information-captured ?SensitiveData)
         (information-obtained ?SensitiveData)
           (information-disclosure ?Application)
           (increase (total-cost) 1)))


(:action attacker-crafts-malicious-json-payload    
  :parameters (?Application - application ?MaliciousPayload - json-payload ?JettisionLibrary - java-library ?CVEID - cve-identifier)
  :precondition (and (exposed-attack-surface ?Application ?CVEID)
               (exploit-by ?CVEID craft-malicious-json-payload))      
  :effect (and (malicious-payload ?MaliciousPayload)
               (deeply-nested-json ?MaliciousPayload)
               (memory-exhaustion-payload ?MaliciousPayload)
               (increase (total-cost) 1)))

(:action attacker-sends-http-post-request-with-malicious-payload
  :parameters (?Application - application ?HTTPRequest - http-post-request ?MaliciousPayload - payload ?ReceiveEndpoint - receive-endpoint ?CVEID - cve-identifier)
  :precondition (and (malicious-payload ?MaliciousPayload)
                     ;(memory-exhaustion-payload ?MaliciousPayload)
                     (has-receive-endpoint ?Application ?ReceiveEndpoint)
                     (exposed-attack-surface ?Application ?CVEID))
  :effect (and (http-post-request-sent ?HTTPRequest)
               (malicious-payload-transmitted ?MaliciousPayload)
                 (increase (total-cost) 1)))


(:action application-receives-http-post-request-with-malicious-payload
  :parameters (?Application - application ?HTTPRequest - http-post-request ?MaliciousPayload - payload ?ReceiveEndpoint - receive-endpoint)
  :precondition (and (http-post-request-sent ?HTTPRequest)
                     (malicious-payload-transmitted ?MaliciousPayload)
                     (has-receive-endpoint ?Application ?ReceiveEndpoint))
  :effect (and (http-post-request-received ?Application ?HTTPRequest)
                 (increase (total-cost) 1)))


(:action application-extracts-json-payload-from-http-request 
 :parameters (?Application - application ?HTTPRequest - http-post-request ?MaliciousPayload - json-payload ?APIEndpoint - api-endpoint)
  :precondition (and  (memory-exhaustion-payload ?MaliciousPayload)
                      (http-post-request-received ?Application ?HTTPRequest)
                     (has-api-endpoint ?Application ?APIEndpoint))
  :effect (and (json-payload-extracted ?Application ?MaliciousPayload)
                 (increase (total-cost) 1)))


(:action application-uses-jettison-json-parser
  :parameters (?Application - application ?JettisionLibrary - java-library ?MaliciousPayload - json-payload)
  :precondition (and (json-payload-extracted ?Application ?MaliciousPayload)
                     (vulnerable-jettison-parser ?JettisionLibrary)
                     (has-library ?Application ?JettisionLibrary))
  :effect (and (jettison-parser-invoked ?JettisionLibrary ?MaliciousPayload)
               (json-parsing-started ?JettisionLibrary)
                (increase (total-cost) 1)))


(:action application-jettison-parser-allocates-heap-memory-for-json-construction   
  :parameters (?JettisionLibrary - java-library ?MaliciousPayload - json-payload ?Application - application)
  :precondition (and (jettison-parser-invoked ?JettisionLibrary ?MaliciousPayload)
                     (json-parsing-started ?JettisionLibrary)
                     (deeply-nested-json ?MaliciousPayload)
                     (memory-exhaustion-payload ?MaliciousPayload)
                     (exposed-attack-surface ?Application CVE_2022_40150))
  :effect (and (heap-memory-allocated ?JettisionLibrary)
               (json-object-graph-construction ?JettisionLibrary)
               (excessive-heap-memory-consumption ?Application)
                 (increase (total-cost) 1)))

(:action application-triggers-OUTOFMEMORY-error
  :parameters (?Application - application ?CVEID - cve-identifier)
  :precondition (and (excessive-heap-memory-consumption ?Application)
                   (exposed-attack-surface ?Application ?CVEID))
  :effect (and (heap-memory-exhausted ?Application)
               ;(garbage-collection-capacity-exceeded ?Application)
               (out-of-memory-error ?Application)
               (memory-exhausted ?Application)
               (resource-exhausted ?Application)
              (application-unresponsive ?Application)
               ;(denial-of-service ?Application)
                 (increase (total-cost) 1)))

(:action attacker-crafts-malicious-xml-payload
  :parameters (?Application - application ?MaliciousPayload - xml-payload ?JettisionLibrary - java-library ?CVEID - cve-identifier)
  :precondition (and (exposed-attack-surface ?Application ?CVEID)
                   (exploit-by ?CVEID craft-malicious-xml-payload))      
  :effect (and (malicious-payload ?MaliciousPayload)
               (deeply-nested-xml ?MaliciousPayload)
               (memory-exhaustion-payload ?MaliciousPayload)
                 (increase (total-cost) 1)))
  
 (:action application-extracts-xml-payload-from-http-request
 :parameters (?Application - application ?HTTPRequest - http-post-request ?MaliciousPayload - xml-payload ?SOAPEndpoint - soap-endpoint)
  :precondition (and (http-post-request-received ?Application ?HTTPRequest)
                     (has-soap-endpoint ?Application ?SOAPEndpoint)
                     (memory-exhaustion-payload ?MaliciousPayload))
  :effect (and (xml-payload-extracted ?Application ?MaliciousPayload)
               (increase (total-cost) 1)))

  (:action application-invokes-jettison-xml-to-json-transformation
  :parameters (?Application - application ?JettisionLibrary - java-library ?MaliciousPayload - xml-payload ?TransformedPayload - json-payload)
  :precondition (and (xml-payload-extracted ?Application ?MaliciousPayload)
                     (vulnerable-jettison-parser ?JettisionLibrary)
                     (has-library ?Application ?JettisionLibrary)
                     (deeply-nested-xml ?MaliciousPayload))
  :effect (and (xml-to-json-transformation-started ?JettisionLibrary ?MaliciousPayload)
               (json-payload ?TransformedPayload)
               (deeply-nested-json ?TransformedPayload)
               (memory-exhaustion-payload ?TransformedPayload)
               (json-payload-extracted ?Application ?TransformedPayload)
                 (increase (total-cost) 1)))

(:action application-jettison-parser-allocates-stack-memory-for-json-construction
  :parameters (?JettisionLibrary - java-library ?MaliciousPayload - json-payload ?Application - application)
  :precondition (and (jettison-parser-invoked ?JettisionLibrary ?MaliciousPayload)
                     (json-parsing-started ?JettisionLibrary)
                     (deeply-nested-json ?MaliciousPayload)
                     (memory-exhaustion-payload ?MaliciousPayload)
                     (exposed-attack-surface ?Application CVE_2022_40149))
  :effect (and (stack-memory-allocated ?JettisionLibrary)
               (json-object-graph-construction ?JettisionLibrary)
               (excessive-stack-memory-consumption ?Application)
              (increase (total-cost) 1)))

(:action application-triggers-STACKOVERFLOW-error
  :parameters (?Application - application ?CVEID - cve-identifier)
  :precondition (and (excessive-stack-memory-consumption ?Application)
                  (exposed-attack-surface ?Application ?CVEID))
  :effect (and (stack-memory-exhausted ?Application)
               ;(garbage-collection-capacity-exceeded ?Application)
               (out-of-memory-error ?Application)
               (memory-exhausted ?Application)
               (resource-exhausted ?Application)
                (increase (total-cost) 1)))


(:action attacker-crafts-malicious-serialized-payload
  :parameters (?Application - application ?MaliciousPayload - serialized-payload ?CVEID - cve-identifier)
  :precondition (and (exposed-attack-surface ?Application ?CVEID)
             (exploit-by ?CVEID craft-malicious-serialized-payload))      
  :effect (and (malicious-payload ?MaliciousPayload)
               (deserialization-exploit-payload ?MaliciousPayload)
                 (increase (total-cost) 1)))


(:action attacker-establishes-tcp-connection-with-application
  :parameters (?Application - application ?Server - tcp-server ?TCPConnection - tcp-connection ?TCPEndpoint - tcp-endpoint ?CVEID - cve-identifier)
  :precondition (and (exposed-attack-surface ?Application ?CVEID)
                     (has-server ?Application ?Server)
                     (server-has-tcp-endpoint ?Server ?TCPEndpoint)
                     (server-listens-on-port ?Server)
                     (tcp-endpoint-external-access-allowed ?TCPEndpoint))
  :effect (and (tcp-connection-established ?Server ?TCPConnection)
               (three-way-handshake-completed ?TCPConnection)
                 (increase (total-cost) 1)))


(:action attacker-sends-malicious-payload-through-tcp
  :parameters (?TCPConnection - tcp-connection ?Server - tcp-server ?MaliciousPayload - serialized-payload ?ReceiverComponent - receiver-component)
  :precondition (and (tcp-connection-established ?Server ?TCPConnection)
                     (three-way-handshake-completed ?TCPConnection)
                     (malicious-payload ?MaliciousPayload))
  :effect (and (malicious-payload-transmitted ?MaliciousPayload)
               (payload-sent-through-tcp ?TCPConnection ?MaliciousPayload)
                 (increase (total-cost) 1)))


(:action application-receives-tcp-connection-and-data
  :parameters (?Application - application ?ReceiverComponent - receiver-component ?TCPConnection - tcp-connection ?MaliciousPayload - serialized-payload)
  :precondition (and (payload-sent-through-tcp ?TCPConnection ?MaliciousPayload)
                     (has-receiver-component ?Application ?ReceiverComponent))
  :effect (and (tcp-connection-received ?Application ?TCPConnection)
               (plaintext-data-received ?Application ?MaliciousPayload)
                 (increase (total-cost) 1)))


(:action application-logback-receiver-extracts-serialized-payload
 :parameters (?Application - application ?ReceiverComponent - logback-receiver ?MaliciousPayload - serialized-payload)
  :precondition (and (plaintext-data-received ?Application ?MaliciousPayload)
                     (vulnerable-logback-receiver ?ReceiverComponent)
                     (has-receiver-component ?Application ?ReceiverComponent))
  :effect (and (serialized-payload-extracted ?ReceiverComponent ?MaliciousPayload)
              (increase (total-cost) 1)))


(:action application-logback-receiver-deserializes-payload
  :parameters (?Application - application ?ReceiverComponent - logback-receiver ?MaliciousPayload - serialized-payload)
  :precondition (and (serialized-payload-extracted ?ReceiverComponent ?MaliciousPayload)
                     (vulnerable-logback-receiver ?ReceiverComponent)
                     (deserialization-exploit-payload ?MaliciousPayload))
  :effect (and (deserialization-started ?ReceiverComponent ?MaliciousPayload)
               (malicious-deserialization-triggered ?Application)
                 (increase (total-cost) 1)))


(:action application-deserialization-triggers-resource-exhaustion
  :parameters (?Application - application ?ReceiverComponent - receiver-component ?CVEID - cve-identifier)
  :precondition (and (malicious-deserialization-triggered ?Application)
                     (vulnerable-receiver ?ReceiverComponent)
                     (exposed-attack-surface ?Application ?CVEID))
  :effect (and (infinite-recursion-triggered ?Application)
               (stack-overflow-occurred ?Application)
               (memory-exhausted ?Application)
               (resource-exhausted ?Application)
               (application-unresponsive ?Application)
               (denial-of-service ?Application)
                 (increase (total-cost) 1)))


(:action attacker-establishes-tls-connection-with-application
  :parameters (?Application - application ?TCPserver - tcp-server ?HTTP2Server - http2-server ?TCPConnection - tcp-connection ?TLSConnection - tls-connection ?CVEID - cve-identifier)
  :precondition (and (exposed-attack-surface  ?Application ?CVEID)
                    (tcp-connection-established ?TCPserver ?TCPConnection)
                     (three-way-handshake-completed ?TCPConnection)
                     (has-server ?Application ?HTTP2Server))
  :effect (and (tls-connection-established ?TLSConnection ?HTTP2Server)
               (secure-channel-created ?TLSConnection)
                 (increase (total-cost) 1)))


(:action attacker-sends-http2-settings-frame
  :parameters (?Server - http2-server ?TLSConnection - tls-connection ?SettingsFrame - http2-settings-frame)
  :precondition (and (tls-connection-established ?TLSConnection ?Server)
                     (secure-channel-created ?TLSConnection))
  :effect (and (http2-settings-frame-sent ?SettingsFrame)
               (http2-parameter-negotiation-initiated ?Server)
                 (increase (total-cost) 1)))


(:action application-http2-server-responds-with-settings-frame
  :parameters (?Server - http2-server ?SettingsFrame - http2-settings-frame ?MaxConcurrentStreams - stream-limit)
  :precondition (and (http2-parameter-negotiation-initiated ?Server)
                     (http2-settings-frame-sent ?SettingsFrame))
  :effect (and (http2-settings-frame-response-sent ?Server)
               (http2-max-concurrent-streams-announced ?Server ?MaxConcurrentStreams)
                 (increase (total-cost) 1)))


(:action attacker-sends-settings-ack-frame
  :parameters (?Server - http2-server ?SettingsAckFrame - http2-settings-ack-frame ?MaxConcurrentStreams - stream-limit)
  :precondition (and (http2-settings-frame-response-sent ?Server)
                     (http2-max-concurrent-streams-announced ?Server ?MaxConcurrentStreams))
  :effect (and (http2-settings-ack-frame-sent ?SettingsAckFrame)
               (increase (total-cost) 1)))

(:action application-receives-ack-frame
  :parameters (?Application - application ?Server - http2-server ?SettingsAckFrame - http2-settings-ack-frame)
  :precondition (and (http2-settings-ack-frame-sent ?SettingsAckFrame)
                     (has-server ?Application ?Server))
  :effect (and (http2-settings-ack-frame-received ?SettingsAckFrame)
               (http2-connection-ready ?Server)
                 (increase (total-cost) 1)))


(:action attacker-establishes-http2-connection-with-application
  :parameters (?Application - application ?Server - http2-server ?HTTP2Connection - http2-connection ?SettingsAckFrame - http2-settings-ack-frame ?CVEID -cve-identifier)
  :precondition (and (http2-settings-ack-frame-received ?SettingsAckFrame)
                     (has-server ?Application ?Server))
  :effect (and (http2-connection-established ?HTTP2Connection ?Server)
               (http2-server-ready-for-stream-creation ?Server)
                 (increase (total-cost) 1)))


(:action attacker-initiates-large-number-of-parallel-streams
  :parameters (?Server - http2-server ?HTTP2Connection - http2-connection ?StreamBatch - stream-batch)
  :precondition (and (http2-connection-established ?HTTP2Connection ?Server)
                     (http2-server-ready-for-stream-creation ?Server)
                     (http2-server-rapid-reset-attack-possible ?Server)
                     (rapid-reset-attack-possible ?Server))
  :effect (and (parallel-streams-initiated ?StreamBatch)
               (large-stream-batch-created ?StreamBatch)
               (rapid-stream-creation-started ?Server)
                (increase (total-cost) 1)))


(:action application-server-allocates-stream-resources
  :parameters (?Application - application ?Server - http2-server ?StreamBatch - stream-batch ?ResourcePool - server-resource)
  :precondition (and (parallel-streams-initiated ?StreamBatch)
                     (large-stream-batch-created ?StreamBatch)
                     (http2-server-allocates-stream-resources ?Application ?Server)
                     (has-server ?Application ?Server))
  :effect (and (stream-ids-allocated ?Server ?StreamBatch)
               (cpu-cycles-allocated ?ResourcePool ?StreamBatch)
               (memory-buffers-allocated ?ResourcePool ?StreamBatch)
               (connection-state-allocated ?ResourcePool ?StreamBatch)
               (server-resource-consumed ?Server ?ResourcePool)
                (increase (total-cost) 1)))


(:action attacker-sends-rst-stream-frames-immediately
  :parameters (?Application - application ?Server - http2-server ?StreamBatch - stream-batch ?RstStreamFrames - rst-stream-frame ?ResourcePool - server-resource ?CVEID - cve-identifier)
  :precondition (and (exploit-by ?CVEID reset-http2-streams)
                     (stream-ids-allocated ?Server ?StreamBatch)
                     (server-resource-consumed ?Server ?ResourcePool)
                     (http2-server-allows-immediate-rst-stream ?Application ?Server))
  :effect (and (rst-stream-frames-sent ?RstStreamFrames ?StreamBatch)
               (stream-cancellation-requests-sent ?Server)
                (increase (total-cost) 1)))


(:action application-server-receives-rst-stream-frames-before-complete-process
  :parameters (?Server - http2-server ?RstStreamFrames - rst-stream-frame ?StreamBatch - stream-batch)
  :precondition (and (rst-stream-frames-sent ?RstStreamFrames ?StreamBatch)
                     (stream-cancellation-requests-sent ?Server)
                     (http2-server-processes-rst-stream-frame ?Server))
  :effect (and (rst-stream-frames-received ?Server ?RstStreamFrames)
               (stream-cancellation-processing-triggered ?Server)
                (increase (total-cost) 1)))


(:action application-server-attempts-rst-stream-processing
  :parameters (?Server - http2-server ?RstStreamFrames - rst-stream-frame ?ResourcePool - server-resource)
  :precondition (and (rst-stream-frames-received ?Server ?RstStreamFrames)
                     (stream-cancellation-processing-triggered ?Server)
                     (server-resource-consumed ?Server ?ResourcePool)
                     (vulnerable-http2-server ?Server))
  :effect (and (rst-stream-processing-attempted ?Server)
               (resource-deallocation-attempted ?Server ?ResourcePool)
               (processing-pace-insufficient ?Server)
                (increase (total-cost) 1)))


(:action application-http2-server-resource-exhausted
  :parameters (?Application - application ?Server - http2-server ?ResourcePool - server-resource)
  :precondition (and (processing-pace-insufficient ?Server)
                     (resource-deallocation-attempted ?Server ?ResourcePool)
                     (insufficient-resource-limits ?Application ?Server)
                     (has-server ?Application ?Server)
                     (vulnerable-http2-server ?Server))
  :effect (and (cpu-cycles-exhausted ?ResourcePool)
               (memory-buffers-exhausted ?ResourcePool)
               (connection-state-exhausted ?ResourcePool)
               (server-resource-exhausted ?Server)
               (resource-exhausted ?Application)
                (increase (total-cost) 1)))

(:action user-sets-weak-password-longer-than-72-chars
  :parameters (?User - user ?Application - application ?Password - password)
  :precondition (and
    (user-needs-to-use-application ?User ?Application))
  :effect (and
    (user-password-set ?User ?Password)
    (password-longer-than-72-chars ?Password)
    (weak-first-72-chars ?Password)
    (user-has-long-weak-password ?User ?Password ?Application)
    (user-has-valid-credentials-application ?User ?Password ?Application) 
     (increase (total-cost) 108)))

(:action application-hashes-and-stores-first-72-chars-only
  :parameters (?User - user ?Application - application ?Password - password ?PasswordHash - password-hash ?PasswordEncoder - password-encoder ?CVEID - cve-identifier)
  :precondition (and
    (exposed-attack-surface ?Application ?CVEID)
    (user-password-set ?User ?Password)
    (password-longer-than-72-chars ?Password)
    (use-bcrypt-password-encoder ?Application ?PasswordEncoder))
  :effect (and
    (password-truncated-to-72-chars ?Password)
    (password-hash-created ?PasswordHash ?Password)
    (password-hash-saved ?PasswordHash ?Application)
    (stored-hash-only-covers-first-72-chars ?PasswordHash)
     (increase (total-cost) 1) ))

(:action attacker-crafts-online-brute-force-script
  :parameters (?Script - script ?Application - application ?PasswordHash - password-hash ?CVEID - cve-identifier)
  :precondition (and
    (exploit-by ?CVEID online-brute-force)
    (online-brute-force-script ?Script)
    (password-hash-saved ?PasswordHash ?Application)
    (stored-hash-only-covers-first-72-chars ?PasswordHash))
  :effect (and
    (malicious-script ?Script)
    (script-targets-application ?Script ?Application)
    (automated-brute-force-capability ?Script)
    (script-generates-long-passwords ?Script)
     (increase (total-cost) 1)))

(:action attacker-sends-large-amount-automated-login-requests-via-script
  :parameters (?Script - script ?Application - application ?LoginRequest - login-request ?InputPassword - password)
  :precondition (and
    (malicious-script ?Script)
    (online-brute-force-script ?Script)
    (script-targets-application ?Script ?Application)
    (automated-brute-force-capability ?Script)
    (not (account-lockout-policy ?Application))
    (not (rate-limiting-enabled ?Application)))
  :effect (and
    (large-volume-login-requests-sent ?LoginRequest ?Application)
    (request-contains-long-password ?LoginRequest ?InputPassword)
    (brute-force-attack-initiated ?Application)
    (requests-bypass-detection ?LoginRequest ?Application)
     (increase (total-cost) 1)))

(:action application-receives-login-requests
  :parameters (?Application - application ?LoginRequest - login-request ?InputPassword - password)
  :precondition (and
    (large-volume-login-requests-sent ?LoginRequest ?Application)
    (request-contains-long-password ?LoginRequest ?InputPassword))
  :effect (and
    (login-request-received ?LoginRequest ?Application)
     (increase (total-cost) 1)))

(:action application-truncates-input-password-to-72-chars
  :parameters (?Application - application ?LoginRequest - login-request ?PasswordEncoder - password-encoder ?InputPassword - password)
  :precondition (and
    (login-request-received ?LoginRequest ?Application)
    (request-contains-long-password ?LoginRequest ?InputPassword)
    (use-bcrypt-password-encoder ?Application ?PasswordEncoder))
  :effect (and
    (password-input-truncated ?InputPassword)
    (truncated-to-72-chars ?InputPassword)
    (bcrypt-processing-initiated ?InputPassword)
     (increase (total-cost) 1)))

(:action application-hashes-truncated-72-chars-input
  :parameters (?Application - application ?InputPassword - password ?PasswordEncoder - password-encoder)
  :precondition (and
    (truncated-to-72-chars ?InputPassword)
    (bcrypt-processing-initiated ?InputPassword)
    (use-bcrypt-password-encoder ?Application ?PasswordEncoder)
    (vulnerable-password-validation ?Application) )
  :effect (and
    (input-password-hashed ?InputPassword)
    (hash-ready-for-comparison ?InputPassword)
    (increase (total-cost) 1)))

(:action application-compares-hashes-with-stored-hash
  :parameters (?Application - application ?InputPassword - password ?StoredHash - password-hash)
  :precondition (and
    (input-password-hashed ?InputPassword)
    (hash-ready-for-comparison ?InputPassword)
    (password-hash-saved ?StoredHash ?Application)
    (stored-hash-only-covers-first-72-chars ?StoredHash))
  :effect (and
    (hash-comparison-performed ?InputPassword ?StoredHash)
    (hashes-match ?InputPassword ?StoredHash)
     (increase (total-cost) 1)))
    

(:action application-authenticates-attacker-successfully
  :parameters (?User - user ?Application - application ?InputPassword - password ?StoredHash - password-hash ?CVEID -cve-identifier )
  :precondition (and
    (user-has-valid-credentials-application ?User ?InputPassword ?Application)
    (hash-comparison-performed ?InputPassword ?StoredHash)
    (hashes-match ?InputPassword ?StoredHash)
    (exposed-attack-surface ?Application ?CVEID))
  :effect (and
    (authentication-successful ?Application)
    (unauthorized-access-granted ?Application)
    (information-obtained ?InputPassword)
    (information-disclosure ?Application)
    (elevation-of-privilege ?Application) 
    (spoofing ?Application)
    (increase (total-cost) 1)))

(:action attacker-crafts-malicious-path-traversal-url  
    :parameters (?MaliciousURL - path-traversal-url ?Payload - path-traversal-payload ?SensitiveFile - sensitive-file ?Application - application ?CVEID - cve-identifier)
    :precondition (and 
        (exposed-attack-surface ?Application ?CVEID)
        (sensitive-files-accessible ?Application)
        (exploit-by ?CVEID path-traversal))
    :effect (and 
        (malicious-path-traversal-url ?MaliciousURL)
        (malicious-url ?MaliciousURL)
        (URL-contains-path-traversal-payload ?MaliciousURL ?Payload)
        (payload-targets-sensitive-file ?Payload ?SensitiveFile)
        (path-traversal-url-created ?MaliciousURL)
        (plaintext-payload ?Payload)
        (increase (total-cost) 1)))

(:action attacker-clicks-malicious-url-includes-path-traversal-pyload
   :parameters (?Browser - browser ?MaliciousURL - path-traversal-url)
   :precondition (and (malicious-path-traversal-url ?MaliciousURL)
                      (is-default-browser ?Browser))
   :effect (and (malicious-url-clicked ?MaliciousURL)
                (path-traversal-url-clicked ?MaliciousURL)
                (running-browser ?Browser)
                 (increase (total-cost) 1)))

(:action attacker-browser-sends-malicious-http-get-request-with-path-traversal-payload
    :parameters (?Browser - browser ?HttpGetRequest - http-get-request ?MaliciousURL - path-traversal-url ?Payload - path-traversal-payload)
    :precondition (and 
        (running-browser ?Browser)
        (malicious-path-traversal-url ?MaliciousURL)
        (path-traversal-url-clicked ?MaliciousURL)
        (URL-contains-path-traversal-payload ?MaliciousURL ?Payload))
    :effect (and (http-get-request-sent ?HttpGetRequest)
                 (request-contains-path-traversal-payload ?Payload)
                  (increase (total-cost) 1)))

 (:action application-receives-http-get-request
    :parameters (?HttpGetRequest - http-get-request ?Application - application)
    :precondition (http-get-request-sent ?HttpGetRequest)
    :effect (and (http-get-request-received ?HttpGetRequest ?Application)
                 (http-request-received ?HttpGetRequest ?Application)
                 (increase (total-cost) 1)))

(:action application-matches-request-to-resource-handler
    :parameters (?HttpGetRequest - http-get-request ?TraversalUrl - path-traversal-url ?Payload - payload ?Application - application ?RouterFunction - router-function ?ResourceHandler - resource-handler ?CVEID - cve-identifier)
    :precondition (and 
        (plaintext-payload ?Payload)
        (http-get-request-received ?HttpGetRequest ?Application)
         (request-contains-path-traversal-payload ?Payload)
        (exposed-attack-surface ?Application ?CVEID)
        (has-router-function-configured ?Application ?RouterFunction))
    :effect (and (request-matched-to-handler ?TraversalUrl ?ResourceHandler)
                  (increase (total-cost) 1)))

(:action application-routes-request-to-resource-handler
    :parameters (?TraversalUrl - path-traversal-url ?ResourceHandler - resource-handler ?RouterFunction - router-function)
    :precondition (and 
        (request-matched-to-handler ?TraversalUrl ?ResourceHandler)
        (router-function-serves-static-resources ?RouterFunction))
    :effect (and (request-routed-to-handler ?TraversalUrl ?ResourceHandler)
                  (increase (total-cost) 1)))

(:action application-resource-handler-concatenates-path-without-normalization
    :parameters (?TraversalUrl - path-traversal-url ?ResourceHandler - resource-handler ?Payload - path-traversal-payload ?ConcatenatedPath - filesystem-path ?Application - application)
    :precondition (and 
        (request-routed-to-handler ?TraversalUrl ?ResourceHandler)
        (URL-contains-path-traversal-payload ?TraversalUrl ?Payload)
        (exposed-attack-surface ?Application CVE_2024_38816))
    :effect (and 
        (path-concatenated-without-normalization ?ConcatenatedPath)
        (traversal-payload-in-path ?ConcatenatedPath ?Payload)
        (vulnerable-file-system-path-created ?ConcatenatedPath)
         (increase (total-cost) 1)))


(:action application-reads-content-from-concatenated-path
    :parameters (?ConcatenatedPath - filesystem-path  ?Payload - path-traversal-payload ?SensitiveFile - sensitive-file ?Data - sensitive-information ?Application - application)
    :precondition (and 
        (vulnerable-file-system-path-created ?ConcatenatedPath)
        (payload-targets-sensitive-file ?Payload ?SensitiveFile)
        (located-at ?SensitiveFile ?ConcatenatedPath)
        (has-filesystem-read-access ?Application)
        (data-stored-in-file ?Data ?SensitiveFile))
    :effect (and (sensitive-data-read-from-filesystem ?Data ?ConcatenatedPath)
            (sensitive-data-prepared-by-application ?Application ?Data)
             (increase (total-cost) 1)))

(:action application-server-returns-sensitive-information 
    :parameters (?HttpGetRequest - http-get-request ?Data - sensitive-information ?Application - application)
    :precondition (and 
        (sensitive-data-prepared-by-application ?Application ?Data)
        (http-get-request-received ?HttpGetRequest ?Application))
    :effect (and (sensitive-data-sent-to-attacker ?Data)
                 (increase (total-cost) 1)))

(:action attacker-receives-sensitive-information   
    :parameters (?Application - application ?Data - sensitive-information ?CVEID - cve-identifier)
    :precondition (and (exposed-attack-surface ?Application ?CVEID)
                       (sensitive-data-sent-to-attacker ?Data))
    :effect (and (information-obtained ?Data)
                 (information-disclosure ?Application)
                 (increase (total-cost) 1) ))


(:action attacker-crafts-malicious-url-includes-encoded-path-traversal-payload
    :parameters (?MaliciousURL - path-traversal-url ?Payload - path-traversal-payload ?SensitiveFile - sensitive-file ?Application - application ?CVEID - cve-identifier)
    :precondition (and 
        (exposed-attack-surface ?Application ?CVEID)
        (sensitive-files-accessible ?Application)
        (exploit-by ?CVEID path-traversal))
    :effect (and 
        (encoded-payload ?Payload)
        (malicious-path-traversal-url ?MaliciousURL)
        (malicious-url ?MaliciousURL)
        (URL-contains-path-traversal-payload ?MaliciousURL ?Payload)
        (payload-targets-sensitive-file ?Payload ?SensitiveFile)
        (path-traversal-url-created ?MaliciousURL)
         (increase (total-cost) 1)))

(:action application-decodes-payload-in-http-get-request
  :parameters (?HttpGetRequest - http-get-request ?TraversalUrl - url ?Payload - payload ?Application - application)
  :precondition (and (http-get-request-received ?HttpGetRequest ?Application)
                 (encoded-payload ?Payload))
  :effect (and (decoded-payload ?Payload)
           (plaintext-payload ?Payload)
            (increase (total-cost) 1)))

(:action attacker-crafts-malicious-java-class
    :parameters (?Application - application ?MaliciousClass - java-class ?CommandLogic - command-execution-logic ?CVEID - cve-identifier)
    :precondition (and (exposed-attack-surface ?Application ?CVEID)
                       (exploit-by ?CVEID  craft-malicious-java-class)) 
    :effect (and (malicious-java-class ?MaliciousClass)
                 (java-class-contains-command-execution-logic ?MaliciousClass ?CommandLogic)
                  (increase (total-cost) 1)))

(:action attacker-hosts-malicious-class-on-server
    :parameters (?Application - application ?MaliciousClass - java-class ?AttackerServer - controlled-server ?CVEID - cve-identifier)
    :precondition (and (malicious-java-class ?MaliciousClass)
                       (exposed-attack-surface ?Application ?CVEID))
    :effect (and (class-hosted-on-server ?MaliciousClass ?AttackerServer)
                 (malicious-class-accessible ?MaliciousClass)
                  (increase (total-cost) 1)))

(:action attacker-sets-up-malicious-ldap-rmi-registry
    :parameters (?Application - application ?AttackerServer - controlled-server ?LDAPService - ldap-service ?RMIService - rmi-service ?MaliciousClass - java-class ?CVEID - cve-identifier)
    :precondition (and (exposed-attack-surface ?Application ?CVEID)
                    (class-hosted-on-server ?MaliciousClass ?AttackerServer)
                   (malicious-class-accessible ?MaliciousClass))
    :effect (and (malicious-ldap-service ?LDAPService)
                 (malicious-rmi-service ?RMIService)
                 (ldap-service-running ?LDAPService ?AttackerServer)
                 (rmi-service-running ?RMIService ?AttackerServer)
                  (increase (total-cost) 1)))

(:action attacker-generates-jndi-endpoint-with-ldap-or-rmi
    :parameters (?Application - application ?Endpoint - jndi-endpoint ?MaliciousClass - java-class ?LDAPService - ldap-service ?RMIService - rmi-service ?CVEID - cve-identifier)
    :precondition (and (exposed-attack-surface ?Application ?CVEID)
                     (exploit-by ?CVEID jndi-injection)
                      (malicious-class-accessible ?MaliciousClass)
                       (or (malicious-ldap-service ?LDAPService) (malicious-rmi-service ?RMIService)))
    :effect (and (malicious-jndi-endpoint ?Endpoint)
                 (endpoint-to-malicious-class ?Endpoint ?MaliciousClass)
                 (jndi-endpoint-created ?Endpoint)
                  (increase (total-cost) 1)))

(:action attacker-crafts-malicious-yaml-payload
    :parameters (?Application - application ?YAMLPayload - yaml-payload ?GadgetClass - java-gadget-class ?JNDIEndpoint - jndi-endpoint ?MaliciousClass - java-class ?CVEID - cve-identifier)
    :precondition (and (exposed-attack-surface ?Application ?CVEID)
                       (exploit-by ?CVEID yaml-deserialization)
                       (jndi-endpoint-created ?JNDIEndpoint)
                       (malicious-jndi-endpoint ?JNDIEndpoint)
                      (endpoint-to-malicious-class ?JNDIEndpoint ?MaliciousClass))
    :effect (and (malicious-yaml-payload ?YAMLPayload)
                 (malicious-payload ?YAMLPayload)
                 (payload-contains-java-gadget-chains ?YAMLPayload ?GadgetClass)
                 (references-jndi-endpoint ?YAMLPayload ?JNDIEndpoint)
                 (yaml-payload-crafted ?YAMLPayload)
                  (increase (total-cost) 1)))

(:action attacker-sends-malicious-yaml-via-http-post
    :parameters ( ?HTTPRequest - http-post-request ?Application - application ?YAMLPayload - yaml-payload ?Endpoint - yaml-endpoint ?CVEID - cve-identifier)
    :precondition (and (exposed-attack-surface ?Application ?CVEID)
                       (yaml-payload-crafted ?YAMLPayload)
                       (malicious-yaml-payload ?YAMLPayload)
                       (has-external-yaml-endpoint ?Application ?Endpoint))
    :effect (and (http-post-request-sent ?HTTPRequest)
                 (request-includes-yaml-payload ?HTTPRequest ?YAMLPayload)
                 (malicious-yaml-transmitted ?YAMLPayload)
                 (malicious-payload-transmitted ?YAMLPayload)
                  (increase (total-cost) 1)))


(:action application-passes-yaml-to-snakeyaml-loader
    :parameters ( ?HTTPRequest - http-post-request ?YAMLPayload - yaml-payload ?Application - application ?SnakeYAML - snakeyaml-library)
    :precondition (and  (http-post-request-received ?Application ?HTTPRequest)
                       (request-includes-yaml-payload ?HTTPRequest ?YAMLPayload)
                       (has-dependency-on-snakeyaml ?Application ?SnakeYAML))
    :effect (and (yaml-passed-to-loader ?YAMLPayload ?SnakeYAML)
                  (increase (total-cost) 1)))

(:action application-starts-yaml-deserialization-with-constructor
    :parameters (?YAMLPayload - yaml-payload ?SnakeYAML - snakeyaml-library ?Constructor - yaml-constructor ?Application - application)
    :precondition (and (yaml-passed-to-loader ?YAMLPayload ?SnakeYAML)
                       (uses-default-constructor ?Application)
                       (not (has-yaml-type-restrictions ?Application)))
    :effect (and (yaml-deserialization-started ?YAMLPayload ?Constructor)
                 (running-constructor ?Constructor)
                  (increase (total-cost) 1)))

(:action application-instantiates-dangerous-java-gadget-class
    :parameters (?Application - application ?Constructor - yaml-constructor ?GadgetClass - java-gadget-class ?YAMLPayload - yaml-payload ?CVEID - cve-identifier)
    :precondition (and (running-constructor ?Constructor)
                       (exposed-attack-surface ?Application ?CVEID)
                       (yaml-deserialization-started ?YAMLPayload ?Constructor)
                       (payload-contains-java-gadget-chains ?YAMLPayload ?GadgetClass))
    :effect (and (dangerous-gadget-class-instantiated ?GadgetClass)
                 (gadget-class-active ?GadgetClass)
                  (increase (total-cost) 1)))


(:action application-loads-malicious-class-from-jndi-endpoint
    :parameters ( ?Application - application ?GadgetClass - java-gadget-class ?JNDIEndpoint - jndi-endpoint ?MaliciousClass - java-class ?YAMLPayload - yaml-payload ?CVEID - cve-identifier)
    :precondition (and (exposed-attack-surface ?Application ?CVEID)
                       (gadget-class-active ?GadgetClass)
                       (references-jndi-endpoint ?YAMLPayload ?JNDIEndpoint)
                       (endpoint-to-malicious-class ?JNDIEndpoint ?MaliciousClass))
    :effect (and (malicious-class-loaded ?MaliciousClass)
                 (jndi-lookup-executed ?JNDIEndpoint)
                  (increase (total-cost) 1)))

(:action application-instantiates-malicious-attacker-class
    :parameters (?Application - application ?Constructor - yaml-constructor ?MaliciousClass - java-class  ?CVEID - cve-identifier)
    :precondition (and (exposed-attack-surface ?Application ?CVEID)
                       (running-constructor ?Constructor)
                       (malicious-class-loaded ?MaliciousClass)
                       (not (has-yaml-type-restrictions ?Application)))
    :effect (and (malicious-class-instantiated ?MaliciousClass)
                 (attacker-class-active ?MaliciousClass)
                  (increase (total-cost) 1)))

(:action application-executes-attacker-command-with-privileges
    :parameters (?Application - application ?MaliciousClass - java-class ?CommandLogic - command-execution-logic ?CVEID - cve-identifier)
    :precondition (and (exposed-attack-surface ?Application ?CVEID)
                      (attacker-class-active ?MaliciousClass)
                      (java-class-contains-command-execution-logic ?MaliciousClass ?CommandLogic)
                      (has-sufficient-code-execution-privilege ?Application))
    :effect (and (attacker-commands-executed ?CommandLogic)
                 (elevation-of-privilege ?Application)
                  (increase (total-cost) 1)))

(:action attacker-crafts-http-get-request-with-internal-dot-path-manipulation  
    :parameters (?HTTPGETRequest - http-get-request ?SensitiveFile - sensitive-file ?PublicDir - public-directory ?SensitiveDir - sensitive-directory ?Application - application ?CVEID - cve-identifier)
    :precondition (and 
        (exposed-attack-surface ?Application ?CVEID)
        (exploit-by ?CVEID internal-dot-path-manipulation)
        (has-public-directory ?Application ?PublicDir)
        (public-directory-has-sensitive-subdirectory ?PublicDir ?SensitiveDir)
        (located-at ?SensitiveFile ?SensitiveDir)
        (sensitive-filename-exposed ?Application ?SensitiveFile))
    :effect (and 
        (malicious-http-get-request ?HTTPGETRequest)
        (request-includes-internal-dot-path-manipulation ?HTTPGETRequest)
        (request-targets-sensitive-file ?HTTPGETRequest ?SensitiveFile) 
        (increase (total-cost) 1)))

(:action attacker-sends-malicious-http-get-request-to-tomcat     
    :parameters (?HttpGetRequest - http-get-request ?Application - application ?Tomcat - tomcat ?CVEID - cve-identifier)
    :precondition (and 
        (exposed-attack-surface ?Application ?CVEID)
       (malicious-http-get-request ?HTTPGETRequest)
        (request-includes-internal-dot-path-manipulation ?HTTPGETRequest)
        (has-tomcat ?Application ?Tomcat))
    :effect (and 
        (http-get-request-sent ?HttpGetRequest)
        (malicious-request-sent-to-tomcat ?HTTPGETRequest ?Tomcat)
        (increase (total-cost) 1)))

(:action application-tomcat-default-servlet-processes-request-without-proper-validation
    :parameters (?HTTPRequest - http-request ?Application - application ?DefaultServlet - default-servlet ?Tomcat - tomcat)
    :precondition (and 
        (http-request-received ?HTTPRequest ?Application)
        (request-includes-internal-dot-path-manipulation ?HTTPRequest)
        (has-tomcat ?Application ?Tomcat)
        (tomcat-has-default-servlet ?Application ?DefaultServlet)
        (vulnerable-tomcat-default-servlet ?Tomcat ?DefaultServlet)
        (not (has-proper-path-equivalence-validation-for-filename  ?Application))
    )
    :effect (and 
        (default-servlet-processing-request ?DefaultServlet ?HTTPRequest)
        (path-parsing-without-validation ?HTTPRequest)
        (internal-dot-section-ignored ?HTTPRequest)
        (increase (total-cost) 1)))

(:action application-tomcat-default-servlet-incorrectly-normalizes-path
    :parameters (?HTTPRequest - http-request ?DefaultServlet - default-servlet ?Tomcat - tomcat ?Application - application)
    :precondition (and 
        (default-servlet-processing-request ?DefaultServlet ?HTTPRequest)
        (vulnerable-tomcat-default-servlet ?Tomcat ?DefaultServlet)
        (path-parsing-without-validation ?HTTPRequest)
        (not (has-proper-path-normalization-for-filename ?Application)))
    :effect (and 
        (path-incorrectly-normalized ?HTTPRequest)
        (access-restrictions-bypassed ?HTTPRequest)
        (increase (total-cost) 1)))


(:action application-tomcat-default-servlet-accesses-sensitive-file
    :parameters (?Application - application ?HTTPRequest - http-request ?DefaultServlet - default-servlet ?SensitiveFile - sensitive-file ?SensitiveDir - sensitive-directory ?Data - sensitive-information)
    :precondition (and 
        (path-incorrectly-normalized ?HTTPRequest)
        (access-restrictions-bypassed ?HTTPRequest)
        (request-targets-sensitive-file ?HTTPRequest ?SensitiveFile)
        (located-at ?SensitiveFile ?SensitiveDir)
        (data-stored-in-file ?Data ?SensitiveFile))
    :effect (and 
        (sensitive-file-located ?SensitiveFile)
        (sensitive-file-accessed ?SensitiveFile)
        (sensitive-data-prepared-by-application ?Application ?Data)
        (increase (total-cost) 1)))


(:action attacker-creates-malicious-content-for-injection
    :parameters (?Application - application ?MaliciousContent - malicious-content ?SensitiveFile - sensitive-file ?CVEID - cve-identifier)
    :precondition (and 
        (exposed-attack-surface ?Application ?CVEID)
        (sensitive-filename-exposed ?Application ?SensitiveFile))
    :effect (and 
        (malicious-content-created ?MaliciousContent)
        (content-targets-sensitive-file ?MaliciousContent ?SensitiveFile)
        (increase (total-cost) 1)))

(:action attacker-crafts-http-put-request-with-internal-dot-path-manipulation
    :parameters (?HTTPPUTRequest - http-put-request ?SensitiveFile - sensitive-file ?PublicDir - public-directory ?SensitiveDir - sensitive-directory ?Application - application ?MaliciousContent - malicious-content ?CVEID - cve-identifier)
    :precondition (and 
        (exposed-attack-surface ?Application ?CVEID)
        (exploit-by ?CVEID internal-dot-path-manipulation)
        (has-public-directory ?Application ?PublicDir)
        (public-directory-has-sensitive-subdirectory ?PublicDir ?SensitiveDir)
        (located-at ?SensitiveFile ?SensitiveDir)
        (sensitive-filename-exposed ?Application ?SensitiveFile)
        (malicious-content-created ?MaliciousContent)
        (content-targets-sensitive-file ?MaliciousContent ?SensitiveFile))
    :effect (and 
        (malicious-http-put-request ?HTTPPUTRequest)
        (request-includes-internal-dot-path-manipulation ?HTTPPUTRequest)
        (put-request-targets-sensitive-file ?HTTPPUTRequest ?SensitiveFile)
        (request-targets-sensitive-file ?HTTPPUTRequest ?SensitiveFile)
        (put-request-contains-malicious-content ?HTTPPUTRequest ?MaliciousContent)
        (increase (total-cost) 1)))


(:action attacker-includes-content-range-headers-for-partial-put
    :parameters (?HTTPPUTRequest - http-put-request ?ContentRangeHeaders - content-range-headers ?Application - application ?CVEID - cve-identifier)
    :precondition (and 
        (exposed-attack-surface ?Application ?CVEID)
        (exploit-by ?CVEID craft-partial-put-request)
        (malicious-http-put-request ?HTTPPUTRequest)
        (request-includes-internal-dot-path-manipulation ?HTTPPUTRequest))
    :effect (and 
        (partial-put-headers-configured ?ContentRangeHeaders)
        (increase (total-cost) 1)))

(:action attacker-sends-malicious-partial-http-put-request-to-tomcat
    :parameters (?HTTPPUTRequest - http-put-request ?ContentRangeHeaders - content-range-headers ?Application - application ?Tomcat - tomcat ?MaliciousContent - malicious-content ?CVEID - cve-identifier)
    :precondition (and 
        (exposed-attack-surface ?Application ?CVEID)
        (exploit-by ?CVEID craft-partial-put-request)
        (has-tomcat ?Application ?Tomcat)
        (partial-put-request-enabled ?Application)
        (malicious-http-put-request ?HTTPPUTRequest)
        (partial-put-headers-configured ?ContentRangeHeaders)
        (request-includes-internal-dot-path-manipulation ?HTTPPUTRequest)
        (put-request-contains-malicious-content ?HTTPPUTRequest ?MaliciousContent))
    :effect (and 
        (http-put-request-sent ?HTTPPUTRequest)
        (put-request-includes-malicious-content ?HTTPPUTRequest)
        (increase (total-cost) 1)))

(:action application-receives-http-put-request
    :parameters (?HTTPPUTRequest - http-put-request ?Application - application)
    :precondition (http-put-request-sent ?HTTPPUTRequest)
    :effect (and (http-put-request-received ?HTTPPUTRequest ?Application)
                 (http-request-received ?HTTPPUTRequest ?Application)
                 (increase (total-cost) 1)))


(:action application-tomcat-default-servlet-writes-malicious-content-to-sensitive-file
    :parameters (?Application - application ?HTTPPUTRequest - http-put-request ?DefaultServlet - default-servlet ?SensitiveFile - sensitive-file ?MaliciousContent - malicious-content ?CVEID - cve-identifier)
    :precondition (and 
        (http-put-request-received ?HTTPPUTRequest ?Application)
        (partial-put-request-enabled ?Application)
        (tomcat-default-servlet-write-enabled ?Application ?DefaultServlet)
        (exposed-attack-surface ?Application ?CVEID)
        (sensitive-file-accessed ?SensitiveFile)
        (put-request-contains-malicious-content ?HTTPPUTRequest ?MaliciousContent)
        (put-request-targets-sensitive-file ?HTTPPUTRequest ?SensitiveFile))
    :effect (and 
        (malicious-content-written-to-file ?MaliciousContent ?SensitiveFile)
        (sensitive-file-tampered ?SensitiveFile)
        (tampering ?Application)
        (increase (total-cost) 1)))

(:action attacker-crafts-malicious-web-shell-script
    :parameters (?Application - application ?WebShellScript - web-shell-script ?CVEID - cve-identifier)
    :precondition (and 
        (exposed-attack-surface ?Application ?CVEID)
        (exploit-by ?CVEID craft-malicious-web-shell))
    :effect (and 
        (malicious-web-shell-script ?WebShellScript)
        (web-shell-script-has-command-execution-capability ?WebShellScript)
        (increase (total-cost) 1)))


(:action attacker-sets-server-side-execution-extension
    :parameters (?WebShellScript - web-shell-script ?FileExtension - file-extension ?Application - application ?CVEID - cve-identifier)
    :precondition (and 
        (exposed-attack-surface ?Application ?CVEID)
        (malicious-web-shell-script ?WebShellScript)
        (or (jsp-extension ?FileExtension) (jspx-extension ?FileExtension)))
    :effect (and 
        (web-shell-script-has-execution-extension ?WebShellScript ?FileExtension)
        (server-side-executable ?WebShellScript)
        (increase (total-cost) 1)))


(:action attacker-crafts-http-put-request-for-web-shell-upload
    :parameters (?HTTPPUTRequest - http-put-request ?WebShellScript - web-shell-script ?PublicDir - public-directory ?SensitiveDir - sensitive-directory ?Application - application ?CVEID - cve-identifier ?FileExtension - file-extension)
    :precondition (and 
        (exposed-attack-surface ?Application ?CVEID)
        (has-public-directory ?Application ?PublicDir)
        (public-directory-has-sensitive-subdirectory ?PublicDir ?SensitiveDir)
        (malicious-web-shell-script ?WebShellScript)
        (web-shell-script-has-execution-extension ?WebShellScript ?FileExtension)
        (server-side-executable ?WebShellScript))
    :effect (and 
        (malicious-http-put-request ?HTTPPUTRequest)
        (request-includes-internal-dot-path-manipulation ?HTTPPUTRequest)
        (put-request-contains-web-shell-script ?HTTPPUTRequest ?WebShellScript)
        (put-request-targets-web-directory ?HTTPPUTRequest ?SensitiveDir)
        (increase (total-cost) 1)))


(:action attacker-sends-web-shell-upload-via-http-put-request
    :parameters (?HTTPPUTRequest - http-put-request ?Application - application ?Tomcat - tomcat ?WebShellScript - web-shell-script ?CVEID - cve-identifier)
    :precondition (and 
        (exposed-attack-surface ?Application ?CVEID)
        (has-tomcat ?Application ?Tomcat)
        (partial-put-request-enabled ?Application)
        (malicious-http-put-request ?HTTPPUTRequest)
        (request-includes-internal-dot-path-manipulation ?HTTPPUTRequest)
        (put-request-contains-web-shell-script ?HTTPPUTRequest ?WebShellScript))
    :effect (and 
        (http-put-request-sent ?HTTPPUTRequest)
        (increase (total-cost) 1)))


(:action application-tomcat-default-servlet-accesses-web-directory
    :parameters (?Application - application ?HTTPPUTRequest - http-put-request ?DefaultServlet - default-servlet ?SensitiveDir - sensitive-directory)
    :precondition (and 
        (path-incorrectly-normalized ?HTTPPUTRequest)
        (access-restrictions-bypassed ?HTTPPUTRequest)
        (put-request-targets-web-directory ?HTTPPUTRequest ?SensitiveDir))
    :effect (and 
        (web-directory-located ?SensitiveDir)
        (web-directory-accessed ?SensitiveDir)
        (increase (total-cost) 1)))

(:action application-tomcat-default-servlet-writes-web-shell-to-directory
    :parameters (?Application - application ?HTTPPUTRequest - http-put-request ?DefaultServlet - default-servlet ?WebShellScript - web-shell-script ?SensitiveDir - sensitive-directory ?CVEID - cve-identifier)
    :precondition (and 
        (exposed-attack-surface ?Application ?CVEID)
        (http-put-request-received ?HTTPPUTRequest ?Application)
        (partial-put-request-enabled ?Application)
        (tomcat-default-servlet-write-enabled ?Application ?DefaultServlet)
        (web-directory-accessed ?SensitiveDir)
        (put-request-contains-web-shell-script ?HTTPPUTRequest ?WebShellScript)
        (put-request-targets-web-directory ?HTTPPUTRequest ?SensitiveDir))
    :effect (and 
        (web-shell-script-written-to-directory ?WebShellScript ?SensitiveDir)
        (web-shell-script-uploaded-successfully ?WebShellScript)
        (web-shell-script-accessible-via-http ?WebShellScript)
        (increase (total-cost) 1)))


(:action attacker-sends-http-get-request-to-web-shell
    :parameters (?HTTPGETRequest - http-get-request ?WebShellScript - web-shell-script ?Application - application ?CVEID - cve-identifier)
    :precondition (and 
        (exposed-attack-surface ?Application ?CVEID)
        (web-shell-script-uploaded-successfully ?WebShellScript)
        (web-shell-script-accessible-via-http ?WebShellScript))
    :effect (and 
        (http-get-request-sent ?HTTPGETRequest)
        (request-includes-web-shell-script ?HTTPGETRequest)
        (get-request-targets-web-shell-script ?HTTPGETRequest ?WebShellScript)
        (increase (total-cost) 1)))
      
(:action application-tomcat-jsp-engine-processes-web-shell
    :parameters (?HTTPGETRequest - http-get-request ?Application - application ?Tomcat - tomcat ?JSPEngine - jsp-engine ?WebShellScript - web-shell-script)
    :precondition (and 
        (has-tomcat ?Application ?Tomcat)
        (tomcat-has-jsp-engine ?Tomcat ?JSPEngine)
        (tomcat-jsp-engine-enabled ?Application ?Tomcat)
        ;; (web-shell-script-access-request-received ?Application ?WebShellScript)
        (http-get-request-received ?HTTPGETRequest ?Application)
        (get-request-targets-web-shell-script ?HTTPGETRequest ?WebShellScript)
        (server-side-executable ?WebShellScript)
        (web-shell-script-has-command-execution-capability ?WebShellScript))
    :effect (and 
        (jsp-engine-processing-web-shell-script ?JSPEngine ?WebShellScript)
        (web-shell-script-parsed ?WebShellScript)
        (increase (total-cost) 1)))

(:action application-tomcat-jsp-engine-executes-web-shell
    :parameters (?Application - application ?JSPEngine - jsp-engine ?WebShellScript - web-shell-script ?TomcatProcess - tomcat-process)
    :precondition (and 
        (jsp-engine-processing-web-shell-script ?JSPEngine ?WebShellScript)
        (web-shell-script-parsed ?WebShellScript)
        (web-shell-script-has-command-execution-capability ?WebShellScript)
        (has-tomcat-process ?Application ?TomcatProcess))
    :effect (and 
        (web-shell-script-executed-with-privileges ?WebShellScript ?TomcatProcess)
        (command-execution-capability-available ?WebShellScript)
        (web-shell-interface-active ?WebShellScript)
        (increase (total-cost) 1)))

(:action attacker-executes-arbitrary-commands-via-web-shell
    :parameters (?WebShellScript - web-shell-script ?TomcatProcess - tomcat-process ?Application - application)
    :precondition (and 
        (web-shell-script-executed-with-privileges ?WebShellScript ?TomcatProcess)
        (command-execution-capability-available ?WebShellScript)
        (web-shell-interface-active ?WebShellScript))
    :effect (and 
        (arbitrary-command-execution ?WebShellScript)
        (system-commands-executed ?TomcatProcess)
        (elevation-of-privilege ?Application)
        (increase (total-cost) 1)))

(:action attacker-identifies-application-default-java-temp-directory
    :parameters (?Application - application ?CVEID - cve-identifier ?TempDir - temporary-directory)
    :precondition (and 
        (exposed-attack-surface ?Application ?CVEID)
        (exploit-by ?CVEID temp-file-prediction)
        (java-tmpdir-set-to-world-writable ?Application)
    )
    :effect (and 
        (temp-directory-identified ?TempDir)
        (attacker-knows-temp-location ?TempDir)
        (increase (total-cost) 1)))

(:action attacker-predicts-temp-file-naming-pattern
    :parameters (?Application - application ?NamingPattern - filename-pattern ?CVEID - cve-identifier ?TempDir - temporary-directory)
    :precondition (and 
        (exposed-attack-surface ?Application ?CVEID)
         (exploit-by ?CVEID temp-file-prediction)
        (uses-predictable-temp-filenames ?Application)
        (temp-directory-identified ?TempDir)
        (attacker-knows-temp-location ?TempDir)
    )
    :effect (and 
        (filename-pattern-predicted ?NamingPattern)
        (attacker-knows-naming-pattern ?NamingPattern)
        (increase (total-cost) 1)))


(:action attacker-creates-symbolic-link-to-sensitive-file
    :parameters (?App - application ?Host - host-os ?SymLink - symbolic-link ?TempDir - temporary-directory ?SensitiveFile - sensitive-system-file 
                 ?PredictedName - filename-pattern )
    :precondition (and 
        (temp-directory-identified ?TempDir)
        (filename-pattern-predicted ?PredictedName)
        (attacker-knows-temp-location ?TempDir)
        (attacker-knows-naming-pattern ?PredictedName)
        (has-os ?App ?Host)
        (world-writable-tempdir-permissions ?Host))
    :effect (and 
        (symbolic-link-created ?SymLink)
        (symlink-points-to-file ?SymLink ?SensitiveFile)
        (symlink-placed-in-temp-dir ?SymLink ?TempDir)
        (symlink-uses-predicted-name ?SymLink ?PredictedName)
        (malicious-symlink-prepared ?SymLink)
        (increase (total-cost) 1)))


(:action user-triggers-filebackedoutputstream-functionality-writes-data
    :parameters (?User - user ?Application - application ?SymLink - symbolic-link ?CVEID - cve-identifier)
    :precondition (and 
        (uses-filebackedoutputstream ?Application)
        (writes-sensitive-data-to-temp ?Application)
        (malicious-symlink-prepared ?SymLink)
        (exposed-attack-surface ?Application ?CVEID)
        (exploit-by ?CVEID temp-file-access)
    )
    :effect (and 
        (filebackedoutputstream-triggered ?Application)
        (temp-file-creation-requested ?Application)
        (increase (total-cost) 1)))


(:action application-creates-temp-file-resolving-to-symlink
    :parameters (?Application - application ?TempFile - temporary-file ?SymLink - symbolic-link 
                 ?File - file ?TempDir - temporary-directory)
    :precondition (and 
        (filebackedoutputstream-triggered ?Application)
        (temp-file-creation-requested ?Application)
        (uses-uncontrolled-createtempfile ?Application)
        (malicious-symlink-prepared ?SymLink)
        (symlink-placed-in-temp-dir ?SymLink ?TempDir)
        (symlink-points-to-file ?SymLink ?File)
        (java-tmpdir-set-to-world-writable ?Application)
    )
    :effect (and 
        (temp-file-created ?TempFile)
        (temp-file-resolves-to-symlink ?TempFile ?SymLink)
        (temp-file-actually-points-to ?TempFile ?File)
        (file-creation-exploited ?TempFile)
        (increase (total-cost) 1)))

(:action application-writes-data-into-resolved-sensitive-file-
    :parameters (?Application - application ?TempFile - temporary-file ?SensitiveFile - sensitive-system-file 
                 ?Data - sensitive-information)
    :precondition (and 
        (filebackedoutputstream-triggered ?Application)
        (temp-file-created ?TempFile)
        (temp-file-actually-points-to ?TempFile ?SensitiveFile)
        (writes-sensitive-data-to-temp ?Application)
    )
    :effect (and 
        (data-written-to-temp-file ?Data ?TempFile)
        (sensitive-system-file-overwritten ?SensitiveFile ?Data)
        (unauthorized-file-modification ?SensitiveFile)
        (increase (total-cost) 1)))


(:action attacker-achieves-unauthorized-tampering
    :parameters (?App - application ?SensitiveFile - sensitive-system-file ?Data - sensitive-information)
    :precondition (and 
        (sensitive-system-file-overwritten ?SensitiveFile ?Data)
        (unauthorized-file-modification ?SensitiveFile)
    )
    :effect (and 
        (tampering ?App)
        (tampering-achieved ?SensitiveFile)
        (data-tampering ?Data)
        (system-integrity-compromised ?SensitiveFile)
        (increase (total-cost) 1)))

(:action attacker-creates-symbolic-link-to-attacker-controlled-file
    :parameters (?App - application ?Host - host-os ?SymLink - symbolic-link ?TempDir - temporary-directory ?AttackerControlledFile - controlled-file 
                 ?PredictedName - filename-pattern )
    :precondition (and 
        (temp-directory-identified ?TempDir)
        (filename-pattern-predicted ?PredictedName)
        (attacker-knows-temp-location ?TempDir)
        (attacker-knows-naming-pattern ?PredictedName)
        (has-os ?App ?Host)
        (world-writable-tempdir-permissions ?Host))
    :effect (and 
        (symbolic-link-created ?SymLink)
        (symlink-points-to-file ?SymLink ?AttackerControlledFile)
        (symlink-placed-in-temp-dir ?SymLink ?TempDir)
        (symlink-uses-predicted-name ?SymLink ?PredictedName)
        (malicious-symlink-prepared ?SymLink)
        (increase (total-cost) 1)))

(:action application-writes-data-into-resolved-attacker-controlled-file
    :parameters (?Application - application ?TempFile - temporary-file ?AttackerControlledFile - controlled-file
                 ?Data - sensitive-information)
    :precondition (and 
        (filebackedoutputstream-triggered ?Application)
        (temp-file-created ?TempFile)
        (temp-file-actually-points-to ?TempFile ?AttackerControlledFile)
        (writes-sensitive-data-to-temp ?Application)
    )
    :effect (and 
        (data-written-to-temp-file ?Data ?TempFile)
        (sensitive-data-written-to-attacker-controlled-file ?Data ?AttackerControlledFile)
        (sensitive-data-sent-to-attacker ?Data)
        (increase (total-cost) 1)))

(:action user-triggers-filebackedoutputstream-functionality-buffers-data
    :parameters (?User - user ?Application - application ?CVEID - cve-identifier)
    :precondition (and 
        (uses-filebackedoutputstream ?Application)
        (writes-sensitive-data-to-temp ?Application)
        (exposed-attack-surface ?Application ?CVEID)
        (exploit-by ?CVEID temp-file-access)
    )
    :effect (and 
        (filebackedoutputstream-triggered ?Application)
        (temp-file-creation-requested ?Application)
        (sensitive-data-buffering-initiated ?Application)
        (increase (total-cost) 1)))

(:action application-creates-temp-file-with-insecure-permissions
    :parameters (?Application - application ?TempFile - temporary-file ?TempDir - temporary-directory ?Host - host-os)
    :precondition (and 
        (filebackedoutputstream-triggered ?Application)
        (temp-file-creation-requested ?Application)
        (uses-uncontrolled-createtempfile ?Application)
        (temp-directory-identified ?TempDir)
        (has-os ?Application ?Host)
        (world-readable-tempdir-permissions ?Host)
    )
    :effect (and 
        (temp-file-created ?TempFile)
        (temp-file-in-directory ?TempFile ?TempDir)
        (temp-file-has-insecure-permissions ?TempFile)
        (temp-file-world-readable ?TempFile)
        (file-ready-for-data-write ?TempFile)
        (increase (total-cost) 1)))

(:action application-writes-sensitive-data-to-temp-file
    :parameters (?Application - application ?TempFile - temporary-file ?SensitiveData - sensitive-information)
    :precondition (and 
        (filebackedoutputstream-triggered ?Application)
        (temp-file-created ?TempFile)
        (file-ready-for-data-write ?TempFile)
        (writes-sensitive-data-to-temp ?Application)
        (sensitive-data-buffering-initiated ?Application)
    )
    :effect (and 
        (temp-file-contains-sensitive-data ?TempFile ?SensitiveData)
        (sensitive-data-exposed-in-filesystem ?SensitiveData)
        (temp-file-populated-with-data ?TempFile)
        (increase (total-cost) 1)))


(:action attacker-monitors-and-detects-temp-file
    :parameters (?TempFile - temporary-file ?TempDir - temporary-directory ?FilePattern - filename-pattern ?CVEID - cve-identifier)
    :precondition (and 
        (temp-directory-under-surveillance ?TempDir)
        (temp-file-created ?TempFile)
        (temp-file-in-directory ?TempFile ?TempDir)
        (temp-file-world-readable ?TempFile)
        (temp-file-populated-with-data ?TempFile)
        (attacker-knows-temp-location ?TempDir)
        (exploit-by ?CVEID temp-file-access)
    )
    :effect (and 
        (temp-file-detected ?TempFile)
        (attacker-knows-temp-file-location ?TempFile)
        (file-accessible-for-reading ?TempFile)
        (temp-file-identified-by-pattern ?TempFile ?FilePattern)
        (increase (total-cost) 1)))


(:action attacker-reads-sensitive-data-from-temp-file
    :parameters (?TempFile - temporary-file ?SensitiveData - sensitive-information ?Application - application ?CVEID - cve-identifier)
    :precondition (and 
        (temp-file-detected ?TempFile)
        (attacker-knows-temp-file-location ?TempFile)
        (file-accessible-for-reading ?TempFile)
        (temp-file-contains-sensitive-data ?TempFile ?SensitiveData)
        (sensitive-data-exposed-in-filesystem ?SensitiveData)
        (temp-file-world-readable ?TempFile)
        (exploit-by ?CVEID temp-file-access)
    )
    :effect (and 
        (sensitive-data-accessed-by-attacker ?SensitiveData)
        (data-confidentiality-breached ?SensitiveData)
        (unauthorized-data-access ?SensitiveData)
        (information-disclosure ?Application)
        (increase (total-cost) 1)))


(:action attacker-crafts-malicious-http-request-with-pathological-etag
 :parameters (?Application - application ?MaliciousRequest - http-request ?MaliciousETag - etag-value ?CVEID - cve-identifier)
 :precondition (and (exposed-attack-surface ?Application ?CVEID)
                    (exploit-by ?CVEID craft-malicious-etag-header))
 :effect (and
     (malicious-http-request ?MaliciousRequest)
     (pathological-etag-value ?MaliciousETag)
     (extremely-long-etag ?MaliciousETag)
     (has-if-match-header ?MaliciousRequest ?MaliciousETag)
     (increase (total-cost) 1)))


(:action attacker-opens-tcp-connection
 :parameters (?Application - application ?MaliciousRequest - http-request ?TCPConnection - tcp-connection ?HTTPEndpoint - http-endpoint)
 :precondition (and (malicious-http-request ?MaliciousRequest)
                    (has-http-endpoint ?Application ?HTTPEndpoint)
                    (publicly-accessible ?HTTPEndpoint))
 :effect (and
     (tcp-connection-initiated ?TCPConnection ?HTTPEndpoint)
     (increase (total-cost) 1)))


(:action application-accepts-tcp-connection
 :parameters (?Application - application ?TCPServer - tcp-server  ?TCPConnection - tcp-connection ?HTTPEndpoint - http-endpoint)
 :precondition (tcp-connection-initiated ?TCPConnection ?HTTPEndpoint)
 :effect (and
     (tcp-connection-established ?TCPServer ?TCPConnection)
     (increase (total-cost) 1)))


(:action attacker-sends-crafted-http-request-with-if-match-header
 :parameters (?Application - application ?MaliciousRequest - http-request ?TCPServer - tcp-server ?TCPConnection - tcp-connection ?MaliciousETag - etag-value)
 :precondition (and (malicious-http-request ?MaliciousRequest)
                    (tcp-connection-established ?TCPServer ?TCPConnection)
                    (has-if-match-header ?MaliciousRequest ?MaliciousETag)
                    (pathological-etag-value ?MaliciousETag))
 :effect (and
     (http-request-sent ?MaliciousRequest)
     (malicious-etag-transmitted ?MaliciousETag )
     (increase (total-cost) 1)))
       

(:action application-receives-http-request
 :parameters (?Application - application ?MaliciousRequest - http-request ?TCPServer - tcp-server ?TCPConnection - tcp-connection)
 :precondition (and (http-request-sent ?MaliciousRequest)
                    (tcp-connection-established ?TCPServer ?TCPConnection))
 :effect (and
     (http-request-received ?MaliciousRequest ?Application )
     (increase (total-cost) 1)))

(:action application-server-reads-http-request-bytes
 :parameters (?Application - application ?MaliciousRequest - http-request ?TCPConnection - tcp-connection)
 :precondition (http-request-received ?MaliciousRequest ?Application )
 :effect (and
     (http-request-bytes-read ?Application ?MaliciousRequest)
     (request-parsing-initiated ?Application)
     (increase (total-cost) 1)))

(:action application-extracts-if-match-header-value
 :parameters (?Application - application ?MaliciousRequest - http-request ?MaliciousETag - etag-value ?HTTPEndpoint - http-endpoint)
 :precondition (and (http-request-bytes-read ?Application ?MaliciousRequest)
                    (has-if-match-header ?MaliciousRequest ?MaliciousETag)
                    (has-http-endpoint ?Application ?HTTPEndpoint))
 :effect (and
     (if-match-header-extracted ?Application ?MaliciousETag)
     (etag-value-ready-for-parsing ?MaliciousETag)
     (increase (total-cost) 1)))

(:action application-calls-vulnerable-spring-etag-parsing-routine
 :parameters (?Application - application ?SpringFramework - spring-framework ?MaliciousETag - etag-value ?ETagHandler - etag-handler)
 :precondition (and (if-match-header-extracted ?Application ?MaliciousETag)
                    (vulnerable-etag-parsing ?SpringFramework)
                    (has-etag-handler ?Application ?ETagHandler)
                    (pathological-etag-value ?MaliciousETag))
 :effect (and
     (spring-etag-parser-invoked ?SpringFramework ?MaliciousETag)
     (etag-parsing-started ?SpringFramework)
     (increase (total-cost) 1)))

(:action application-suffers-resource-exhaustion
 :parameters (?Application - application ?CVEID - cve-identifier ?SpringFramework - spring-framework ?MaliciousETag - etag-value)
 :precondition (and (spring-etag-parser-invoked ?SpringFramework ?MaliciousETag)
                    (etag-parsing-started ?SpringFramework)
                    (extremely-long-etag ?MaliciousETag)
                    (pathological-etag-value ?MaliciousETag)
                    (exposed-attack-surface ?Application ?CVEID))
 :effect (and
     (excessive-cpu-consumption ?Application)
     (excessive-memory-consumption ?Application)
     (resource-exhausted ?Application)
     (increase (total-cost) 1)))


(:action attacker-crafts-malicious-binary-xstream-payload    
 :parameters (?Application - application ?MaliciousPayload - binary-payload ?XStreamLibrary - java-library ?CVEID - cve-identifier)
 :precondition (and (exposed-attack-surface ?Application ?CVEID)
                   (exploit-by ?CVEID craft-malicious-binary-payload))      
 :effect (and (malicious-payload ?MaliciousPayload)
              (binary-xstream-payload ?MaliciousPayload)
              (deeply-nested-binary ?MaliciousPayload)
              (recursive-mapping-payload ?MaliciousPayload)
              (stack-exhaustion-payload ?MaliciousPayload)
              (increase (total-cost) 1)))


(:action attacker-sends-http-post-request-with-binary-payload
 :parameters (?Application - application ?HTTPRequest - http-post-request ?MaliciousPayload - binary-payload ?ReceiveEndpoint - receive-endpoint ?CVEID - cve-identifier)
 :precondition (and (malicious-payload ?MaliciousPayload)
                    (binary-xstream-payload ?MaliciousPayload)
                    (has-receive-endpoint ?Application ?ReceiveEndpoint)
                    (exposed-attack-surface ?Application ?CVEID)
                    (exploit-by ?CVEID craft-malicious-binary-payload))
 :effect (and (http-post-request-sent ?HTTPRequest)
              (malicious-payload-transmitted ?MaliciousPayload)
              (increase (total-cost) 1)))


(:action application-extracts-binary-payload-from-http-request 
 :parameters (?Application - application ?HTTPRequest - http-post-request ?MaliciousPayload - binary-payload ?APIEndpoint - api-endpoint)
 :precondition (and (stack-exhaustion-payload ?MaliciousPayload)
                    (http-post-request-received ?Application ?HTTPRequest)
                    (has-api-endpoint ?Application ?APIEndpoint))
 :effect (and (binary-payload-extracted ?Application ?MaliciousPayload)
              (increase (total-cost) 1)))


(:action application-uses-xstream-binary-driver
 :parameters (?Application - application ?XStreamLibrary - java-library ?BinaryDriver - binary-stream-driver ?MaliciousPayload - binary-payload)
 :precondition (and (binary-payload-extracted ?Application ?MaliciousPayload)
                    (vulnerable-xstream-binary-driver ?XStreamLibrary)
                    (has-library ?Application ?XStreamLibrary)
                    (has-binary-stream-driver ?Application ?BinaryDriver))
 :effect (and (xstream-binary-driver-invoked ?XStreamLibrary ?MaliciousPayload)
              (binary-parsing-started ?XStreamLibrary)
              (increase (total-cost) 1)))


(:action application-binary-driver-allocates-stack-frames-for-recursive-decoding
 :parameters (?XStreamLibrary - java-library ?BinaryDriver - binary-stream-driver ?MaliciousPayload - binary-payload ?Application - application ?CVEID - cve-identifier)
 :precondition (and (xstream-binary-driver-invoked ?XStreamLibrary ?MaliciousPayload)
                    (binary-parsing-started ?XStreamLibrary)
                    (deeply-nested-binary ?MaliciousPayload)
                    (recursive-mapping-payload ?MaliciousPayload)
                    (exposed-attack-surface ?Application ?CVEID))
 :effect (and (call-stack-frames-allocated ?XStreamLibrary)
              (recursive-object-graph-construction ?XStreamLibrary)
              (recursive-mapping-token-resolution ?XStreamLibrary)
              (excessive-stack-memory-consumption ?Application)
              (increase (total-cost) 1)))


(:action attacker-crafts-malicious-pem-file
 :parameters (?Application - application ?MaliciousPEMFile - pem-file ?ASN1 - asn1-structure ?CVEID - cve-identifier)
 :precondition (and
      (exploit-by ?CVEID craft-malicious-pem-file)
       (exposed-attack-surface ?Application ?CVEID))
 :effect (and
    (malicious-file ?MaliciousPEMFile)
    (pem-file ?MaliciousPEMFile)
    (file-contains-asn1 ?MaliciousPEMFile ?ASN1)
    (asn1-deeply-nested ?ASN1)
    (asn1-large-lengths ?ASN1)
    (memory-exhaustion-file ?MaliciousPEMFile)
    (increase (total-cost) 1) ))

(:action attacker-sends-malicious-pem-file-to-user
 :parameters (?MaliciousPEMFile - pem-file ?Message - message ?Comchannel - comchannel ?User - user ?Application - application)
 :precondition (and
    (malicious-file ?MaliciousPEMFile)
    (pem-file ?MaliciousPEMFile)
    (has-account ?User ?Application)
 )
 :effect (and
    (malicious-msg ?Message)
    (message-has-file ?Message ?MaliciousPEMFile)
    (com-channel-msg ?Comchannel ?Message)
    (message-sent ?Message)
    (increase (total-cost) 1)))


(:action user-uploads-pem-file-to-application
 :parameters (?User - user ?MaliciousPEMFile - pem-file ?Application - application ?PEMEndpoint - pem-endpoint)
 :precondition (and
    (downloaded ?MaliciousPEMFile)
    (pem-file ?MaliciousPEMFile)
    (has-account ?User ?Application)
    (has-pem-endpoint ?Application ?PEMEndpoint)
    (accepts-pem-input ?Application ?PEMEndpoint)
 )
 :effect (and
    (file-uploaded-to-application ?MaliciousPEMFile ?Application)
    (malicious-file-transmitted ?MaliciousPEMFile)
    (file-targets-endpoint ?MaliciousPEMFile ?PEMEndpoint)
    (increase (total-cost) 171)))



(:action application-receives-pem-file
 :parameters (?Application - application ?MaliciousPEMFile - pem-file ?PEMEndpoint - pem-endpoint)
 :precondition (and 
    (file-uploaded-to-application ?MaliciousPEMFile ?Application)
    (malicious-file-transmitted ?MaliciousPEMFile)
    (has-pem-endpoint ?Application ?PEMEndpoint)
    (file-targets-endpoint ?MaliciousPEMFile ?PEMEndpoint))
 :effect (and 
    (pem-file-received ?Application ?MaliciousPEMFile)
    (increase (total-cost) 1)))

; Application extracts PEM payload (modified from provided)
(:action application-extracts-pem-payload-from-file
 :parameters (?Application - application ?MaliciousPEMFile - pem-file ?MaliciousPEM - pem-payload ?PEMEndpoint - pem-endpoint ?ASN1 - asn1-structure)
 :precondition (and
    (pem-file-received ?Application ?MaliciousPEMFile)
    (pem-file ?MaliciousPEMFile)
    (has-pem-endpoint ?Application ?PEMEndpoint)
 )
 :effect (and
    (pem-payload-extracted ?Application ?MaliciousPEM)
    (payload-from-file ?MaliciousPEM ?MaliciousPEMFile)
    (payload-contains-asn1 ?MaliciousPEM ?ASN1)
    (memory-exhaustion-payload ?MaliciousPEM)
    (increase (total-cost) 1)))
    

(:action attacker-registers-account-on-target-application
    :parameters (?Account - account ?Application - application ?SessionCookie - session-cookie ?CVEID - cve-identifier)
    :precondition (and (exposed-attack-surface ?Application ?CVEID)
                       (exploit-needs-user-account ?CVEID)) 
    :effect (and (account-registered ?Account ?Application)
                 (attacker-has-account ?Account)
                 (session-cookie-obtained ?SessionCookie ?Account)
                 (account-has-normal-privileges ?Account)
                  (increase (total-cost) 1)))


(:action Attacker-uploads-pem-file-to-application
 :parameters (?MaliciousPEMFile - pem-file ?Application - application ?PEMEndpoint - pem-endpoint ?Account - account)
 :precondition (and
    (pem-file ?MaliciousPEMFile)
    (attacker-has-account ?Account)
    (has-pem-endpoint ?Application ?PEMEndpoint)
    (accepts-pem-input ?Application ?PEMEndpoint) )
 :effect (and
    (file-uploaded-to-application ?MaliciousPEMFile ?Application)
    (malicious-file-transmitted ?MaliciousPEMFile)
    (file-targets-endpoint ?MaliciousPEMFile ?PEMEndpoint)
    (increase (total-cost) 1)))

(:action attacker-crafts-malicious-pem-payload
 :parameters (?Application - application ?MaliciousPEM - pem-payload ?ASN1 - asn1-structure ?CVEID - cve-identifier)
 :precondition (and
    (exposed-attack-surface ?Application ?CVEID)
    (exploit-by ?CVEID craft-malicious-pem-payload) )
 :effect (and
    (malicious-pem-payload ?MaliciousPEM)
    (payload-contains-asn1 ?MaliciousPEM ?ASN1)
    (asn1-deeply-nested ?ASN1)
    (asn1-large-lengths ?ASN1)
    (memory-exhaustion-payload ?MaliciousPEM)
    (increase (total-cost) 1)))

(:action attacker-sends-http-post-request-with-malicious-pem
 :parameters (?HTTPRequest - http-post-request ?Application - application ?MaliciousPEM - pem-payload ?PEMEndpoint - pem-endpoint ?CVEID - cve-identifier)
 :precondition (and
    (malicious-pem-payload ?MaliciousPEM)
    (has-pem-endpoint ?Application ?PEMEndpoint)
    (endpoint-reachable-to-attackers ?Application ?PEMEndpoint)
    (exposed-attack-surface ?Application ?CVEID))
 :effect (and
    (http-post-request-sent ?HTTPRequest)
    (malicious-payload-transmitted ?MaliciousPEM)
    (http-request-targets-endpoint ?HTTPRequest ?PEMEndpoint)
    (increase (total-cost) 1)))


(:action application-extracts-pem-payload-from-http-request
 :parameters (?Application - application ?HTTPRequest - http-post-request ?MaliciousPEM - pem-payload ?PEMEndpoint - pem-endpoint)
 :precondition (and
    (http-post-request-received ?Application ?HTTPRequest)
    (malicious-payload-transmitted ?MaliciousPEM)
    (has-pem-endpoint ?Application ?PEMEndpoint)
 )
 :effect (and
    (pem-payload-extracted ?Application ?MaliciousPEM)
    (increase (total-cost) 1)))


(:action application-uses-bouncycastle-pemparser-readobject
 :parameters (?Application - application ?BCLibrary - java-library ?MaliciousPEM - pem-payload)
 :precondition (and
    (pem-payload-extracted ?Application ?MaliciousPEM)
    (has-library ?Application ?BCLibrary)
    (bouncycastle-library ?BCLibrary)
    (vulnerable-bouncycastle ?BCLibrary)
    (parser-in-process ?Application))
 :effect (and
    (pemparser-invoked ?BCLibrary ?MaliciousPEM)
    (pemparsing-started ?BCLibrary)
    (increase (total-cost) 1)))

(:action application-pemparser-allocates-heap-memory-for-asn1-construction
 :parameters (?BCLibrary - java-library ?MaliciousPEM - pem-payload ?ASN1 - asn1-structure ?Application - application)
 :precondition (and
    (pemparser-invoked ?BCLibrary ?MaliciousPEM)
    (pemparsing-started ?BCLibrary)
    (payload-contains-asn1 ?MaliciousPEM ?ASN1)
    (asn1-deeply-nested ?ASN1)
    (asn1-large-lengths ?ASN1)
    (parser-shares-jvm-heap ?Application))
 :effect (and
    (heap-memory-allocated-for-asn1 ?BCLibrary)
    (asn1-object-graph-construction ?BCLibrary)
    (excessive-heap-memory-consumption ?Application)
    (increase (total-cost) 1)))


(:action attacker-opens-new-frontend-tcp-connection-to-reverse-proxy
  :parameters (?Application - application ?Attacker - attacker ?ReverseProxy - reverse-proxy ?TCPServer - tcp-server ?FrontendConnection - tcp-connection ?CVEID - cve-identifier)
  :precondition (and (exposed-attack-surface ?Application ?CVEID)
                      (exploit-by ?CVEID  http-request-smuggling)
                     (has-reverse-proxy ?Application ?ReverseProxy))
  :effect (and (frontend-connection-opened ?Attacker ?ReverseProxy ?FrontendConnection)
               (tcp-connection-established ?TCPServer ?FrontendConnection)
               (increase (total-cost) 1)))

(:action reverse-proxy-accepts-frontend-tcp-connection
  :parameters (?ReverseProxy - reverse-proxy ?TCPServer - tcp-server ?FrontendConnection - tcp-connection ?Attacker - attacker)
  :precondition (and (frontend-connection-opened ?Attacker ?ReverseProxy ?FrontendConnection)
                     (tcp-connection-established ?TCPServer ?FrontendConnection))
  :effect (and (frontend-connection-accepted ?ReverseProxy ?FrontendConnection)
               (attacker-connected-to-proxy ?Attacker ?ReverseProxy)
               (increase (total-cost) 1)))

(:action reverse-proxy-opens-new-backend-tcp-connection-to-application-tomcat
  :parameters (?ReverseProxy - reverse-proxy ?Tomcat - tomcat ?TCPServer - tcp-server ?FrontendConnection - tcp-connection ?BackendConnection - tcp-connection)
  :precondition (and (frontend-connection-accepted ?ReverseProxy ?FrontendConnection)
                     (vulnerable-tomcat ?Tomcat)
                     (forwards-requests ?ReverseProxy ?Tomcat))
  :effect (and (backend-connection-opened ?ReverseProxy ?Tomcat ?BackendConnection)
               (tcp-connection-established ?TCPServer ?BackendConnection)
               (increase (total-cost) 1)))

(:action application-tomcat-accepts-backend-tcp-connection
  :parameters (?Tomcat - tomcat ?TCPServer - tcp-server ?BackendConnection - tcp-connection ?ReverseProxy - reverse-proxy)
  :precondition (and (backend-connection-opened ?ReverseProxy ?Tomcat ?BackendConnection)
                     (tcp-connection-established ?TCPServer ?BackendConnection))
  :effect (and (backend-connection-accepted ?Tomcat ?BackendConnection)
               (proxy-connected-to-tomcat ?ReverseProxy ?Tomcat)
               (increase (total-cost) 1)))

(:action attacker-sends-trigger-http-request-with-oversized-trailer-header-to-desync-application-tomcat
  :parameters (?Attacker - attacker ?Application - application ?ReverseProxy - reverse-proxy ?TriggerRequest - http-request ?FrontendConnection - tcp-connection ?TrailerHeader - trailer-header ?Tomcat - tomcat)
  :precondition (and (attacker-connected-to-proxy ?Attacker ?ReverseProxy)
                     (frontend-connection-accepted ?ReverseProxy ?FrontendConnection)
                     (smuggling-trigger-http-request ?TriggerRequest)
                     (has-tomcat ?Application ?Tomcat)
                     (proxy-connected-to-tomcat ?ReverseProxy ?Tomcat))
  :effect (and (trigger-request-sent ?Attacker ?TriggerRequest)
               (oversized-trailer-header ?TrailerHeader)
               (chunked-encoding-request ?TriggerRequest)
               (desync-payload ?TriggerRequest)
               (increase (total-cost) 1)))

(:action reverse-proxy-receives-partial-http-request-through-the-built-frontend-tcp-connection
  :parameters (?Attacker - attacker ?ReverseProxy - reverse-proxy ?TriggerRequest - http-request ?FrontendConnection - tcp-connection)
  :precondition (and (trigger-request-sent ?Attacker ?TriggerRequest)
                     (frontend-connection-accepted ?ReverseProxy ?FrontendConnection)
                     (desync-payload ?TriggerRequest)
                     (smuggling-trigger-http-request ?TriggerRequest))
  :effect (and (partial-request-received ?ReverseProxy ?TriggerRequest)
               (request-in-proxy-buffer ?TriggerRequest)
               (increase (total-cost) 1)))

(:action reverse-proxy-parses-and-forwards-partial-request-to-application-tomcat-through-backend-connection
  :parameters (?ReverseProxy - reverse-proxy ?TriggerRequest - http-request ?BackendConnection - tcp-connection ?Tomcat - tomcat)
  :precondition (and (partial-request-received ?ReverseProxy ?TriggerRequest)
                     (smuggling-trigger-http-request ?TriggerRequest)
                     (backend-connection-accepted ?Tomcat ?BackendConnection)
                     (proxy-connected-to-tomcat ?ReverseProxy ?Tomcat))
  :effect (and (partial-request-parsed ?ReverseProxy ?TriggerRequest)
               (partial-request-forwarded ?ReverseProxy ?TriggerRequest)
               (request-in-transit-to-tomcat ?TriggerRequest)
               (increase (total-cost) 1)))

(:action application-tomcat-receives-trigger-request-and-interprets-as-complete-request
  :parameters (?ReverseProxy - reverse-proxy ?Tomcat - tomcat ?TriggerRequest - http-request ?BackendConnection - tcp-connection)
  :precondition (and (partial-request-forwarded ?ReverseProxy ?TriggerRequest)
                     (smuggling-trigger-http-request ?TriggerRequest)
                     (request-in-transit-to-tomcat ?TriggerRequest)
                     (backend-connection-accepted ?Tomcat ?BackendConnection))
  :effect (and (trigger-request-received ?Tomcat ?TriggerRequest)
               (complete-request-interpreted ?Tomcat ?TriggerRequest)
               (desync-condition-created ?Tomcat)
               (increase (total-cost) 1)))

(:action application-tomcat-sends-response-or-ack-to-reverse-proxy
  :parameters (?Tomcat - tomcat ?TriggerRequest - http-request ?Response - http-response ?BackendConnection - tcp-connection ?ReverseProxy - reverse-proxy)
  :precondition (and (complete-request-interpreted ?Tomcat ?TriggerRequest)
                     (smuggling-trigger-http-request ?TriggerRequest)
                     (trigger-request-received ?Tomcat ?TriggerRequest)
                     (proxy-connected-to-tomcat ?ReverseProxy ?Tomcat))
  :effect (and (response-sent ?Tomcat ?Response)
               (response-in-transit-to-proxy ?Response)
               (increase (total-cost) 1)))

(:action reverse-proxy-receives-response-or-ack-from-backend-connection
  :parameters (?Tomcat - tomcat ?ReverseProxy - reverse-proxy ?Response - http-response ?BackendConnection - tcp-connection)
  :precondition (and (response-sent ?Tomcat ?Response)
                     (response-in-transit-to-proxy ?Response)
                     (backend-connection-accepted ?Tomcat ?BackendConnection))
  :effect (and (response-received-by-proxy ?ReverseProxy ?Response)
               (response-ready-for-forwarding ?Response)
               (increase (total-cost) 1)))

(:action reverse-proxy-forwards-response-or-ack-to-attacker-through-frontend-connection
  :parameters (?ReverseProxy - reverse-proxy ?Response - http-response ?FrontendConnection - tcp-connection ?Attacker - attacker)
  :precondition (and (response-received-by-proxy ?ReverseProxy ?Response)
                     (response-ready-for-forwarding ?Response)
                     (attacker-connected-to-proxy ?Attacker ?ReverseProxy))
  :effect (and (response-forwarded-to-attacker ?ReverseProxy ?Response)
               (response-in-transit-to-attacker ?Response)
               (increase (total-cost) 1)))

(:action attacker-receives-response-or-ack
  :parameters (?Attacker - attacker ?ReverseProxy - reverse-proxy ?Response - http-response ?FrontendConnection - tcp-connection)
  :precondition (and (response-forwarded-to-attacker ?ReverseProxy ?Response)
                     (response-in-transit-to-attacker ?Response)
                     (frontend-connection-accepted ?ReverseProxy ?FrontendConnection))
  :effect (and (response-received-by-attacker ?Attacker ?Response)
               (smuggling-signal-received ?Attacker)
               (can-send-smuggled-payload ?Attacker)
               (increase (total-cost) 1)))

(:action attacker-sends-additional-smuggled-http-request-targeting-hijack-user-session-on-existing-frontend-connection
  :parameters (?Attacker - attacker ?ReverseProxy - reverse-proxy ?SmuggledRequest - http-request ?FrontendConnection - tcp-connection)
  :precondition (and (can-send-smuggled-payload ?Attacker)
                     (smuggling-http-request-hijack  ?SmuggledRequest)
                     (smuggling-signal-received ?Attacker)
                     (frontend-connection-accepted ?ReverseProxy ?FrontendConnection))
  :effect (and (smuggled-request-sent ?Attacker ?SmuggledRequest)
               (session-hijack-payload ?SmuggledRequest)
               (privilege-escalation-payload ?SmuggledRequest)
               (increase (total-cost) 1)))

(:action reverse-proxy-receives-additional-smuggled-http-request
  :parameters (?Attacker - attacker ?ReverseProxy - reverse-proxy ?SmuggledRequest - http-request ?FrontendConnection - tcp-connection)
  :precondition (and (smuggled-request-sent ?Attacker ?SmuggledRequest)
                     (smuggling-http-request-http  ?SmuggledRequest)
                     ;(session-hijack-payload ?SmuggledRequest)
                     (frontend-connection-accepted ?ReverseProxy ?FrontendConnection))
  :effect (and (smuggled-request-received-by-proxy ?ReverseProxy ?SmuggledRequest)
               (smuggled-payload-in-proxy-buffer ?SmuggledRequest)
               (increase (total-cost) 1)))

(:action reverse-proxy-forwards-additional-smuggled-http-request-to-application-tomcat-on-same-backend-connection
  :parameters (?ReverseProxy - reverse-proxy ?SmuggledRequest - http-request ?BackendConnection - tcp-connection ?Tomcat - tomcat)
  :precondition (and (smuggled-request-received-by-proxy ?ReverseProxy ?SmuggledRequest)
                      (smuggling-http-request-http  ?SmuggledRequest)
                     (smuggled-payload-in-proxy-buffer ?SmuggledRequest)
                     (backend-connection-accepted ?Tomcat ?BackendConnection)
                     (allows-connection-reuse ?ReverseProxy ?Tomcat))
  :effect (and (smuggled-request-forwarded-to-tomcat ?ReverseProxy ?SmuggledRequest)
               (smuggled-request-in-transit-to-tomcat ?SmuggledRequest)
               (increase (total-cost) 1)))

(:action application-tomcat-receives-additional-smuggled-http-request-through-the-built-backend-tcp-connection
  :parameters (?ReverseProxy - reverse-proxy ?Tomcat - tomcat ?SmuggledRequest - http-request ?BackendConnection - tcp-connection)
  :precondition (and (smuggled-request-forwarded-to-tomcat ?ReverseProxy ?SmuggledRequest)
                     (smuggling-http-request-http  ?SmuggledRequest)
                     (smuggled-request-in-transit-to-tomcat ?SmuggledRequest)
                     (backend-connection-accepted ?Tomcat ?BackendConnection))
  :effect (and (smuggled-request-received-by-tomcat ?Tomcat ?SmuggledRequest)
               (smuggled-payload-queued ?Tomcat ?SmuggledRequest)
               (increase (total-cost) 1)))

(:action application-tomcat-interprets-trigger-http-request-and-additional-smuggled-request-as-multiple-separate-requests
  :parameters (?Tomcat - tomcat ?TriggerRequest - http-request ?SmuggledRequest - http-request)
  :precondition (and (complete-request-interpreted ?Tomcat ?TriggerRequest)
                      (smuggling-http-request-http  ?SmuggledRequest)
                     (smuggling-trigger-http-request ?TriggerRequest)
                     (smuggled-request-received-by-tomcat ?Tomcat ?SmuggledRequest)
                     (desync-condition-created ?Tomcat))
  :effect (and (requests-interpreted-separately ?Tomcat ?TriggerRequest ?SmuggledRequest)
               (smuggled-request-ready-for-processing ?SmuggledRequest)
               (request-boundary-confusion ?Tomcat)
               (increase (total-cost) 1)))

(:action user-opens-new-frontend-tcp-connection-to-reverse-proxy
  :parameters (?Application - application ?User - user ?ReverseProxy - reverse-proxy ?SmuggledRequest - http-request ?UserFrontendConnection - tcp-connection)
  :precondition (and  (has-reverse-proxy ?Application ?ReverseProxy)
                      (smuggling-http-request-http  ?SmuggledRequest)
                     (smuggled-request-ready-for-processing ?SmuggledRequest))
  :effect (and (user-frontend-connection-opened ?User ?ReverseProxy ?UserFrontendConnection)
               (user-tcp-connection-established ?UserFrontendConnection)
               (increase (total-cost) 1)))

(:action reverse-proxy-accepts-frontend-tcp-connection-from-user
  :parameters (?ReverseProxy - reverse-proxy ?UserFrontendConnection - tcp-connection ?FrontendConnection - tcp-connection ?User - user)
  :precondition (and (user-frontend-connection-opened ?User ?ReverseProxy ?UserFrontendConnection)
                     (user-tcp-connection-established ?UserFrontendConnection))
  :effect (and (user-frontend-connection-accepted ?ReverseProxy ?UserFrontendConnection)
               (user-connected-to-proxy ?User ?ReverseProxy)
               (increase (total-cost) 1)))

(:action user-sends-http-get-request-for-sensitive-resource
  :parameters (?User - user ?ReverseProxy - reverse-proxy ?UserRequest - http-request ?SensitiveResource - sensitive-information ?UserFrontendConnection - tcp-connection)
  :precondition (and (bond-to-user-account ?User ?SensitiveResource)
                     (user-http-request ?UserRequest)
                     (user-connected-to-proxy ?User ?ReverseProxy)
                     (user-frontend-connection-accepted ?ReverseProxy ?UserFrontendConnection))
  :effect (and (user-request-sent ?User ?UserRequest)
               (targets-sensitive-resource ?UserRequest ?SensitiveResource)
               (authenticated-user-request ?UserRequest)
               (increase (total-cost) 1)))

(:action reverse-proxy-receives-user-http-get-request
  :parameters (?ReverseProxy - reverse-proxy ?User - user ?UserRequest - http-request ?UserFrontendConnection - tcp-connection)
  :precondition (and (user-request-sent ?User ?UserRequest)
                    (user-http-request ?UserRequest)
                     (user-frontend-connection-accepted ?ReverseProxy ?UserFrontendConnection))
  :effect (and (user-request-received-by-proxy ?ReverseProxy ?UserRequest)
               (user-request-in-proxy-buffer ?UserRequest)
               (increase (total-cost) 1)))

(:action reverse-proxy-forwards-user-http-get-request-to-application-tomcat-by-reusing-existing-backend-connection
  :parameters (?ReverseProxy - reverse-proxy ?UserRequest - http-request ?BackendConnection - tcp-connection ?Tomcat - tomcat)
  :precondition (and (user-request-received-by-proxy ?ReverseProxy ?UserRequest)
                     (user-request-in-proxy-buffer ?UserRequest)
                     (user-http-request ?UserRequest)
                     (backend-connection-accepted ?Tomcat ?BackendConnection)
                     (allows-connection-reuse ?ReverseProxy ?Tomcat))
  :effect (and (user-request-forwarded-to-tomcat ?ReverseProxy ?UserRequest)
               (user-request-in-transit-to-tomcat ?UserRequest)
               (connection-reused ?BackendConnection)
               (increase (total-cost) 1)))

(:action application-tomcat-receives-user-http-request
  :parameters (?ReverseProxy - reverse-proxy ?Tomcat - tomcat ?UserRequest - http-request ?BackendConnection - tcp-connection)
  :precondition (and (user-request-forwarded-to-tomcat ?ReverseProxy ?UserRequest)
                     (user-request-in-transit-to-tomcat ?UserRequest)
                     (user-http-request ?UserRequest)
                     (connection-reused ?BackendConnection))
  :effect (and (user-request-received-by-tomcat ?Tomcat ?UserRequest)
               (user-request-queued-for-processing ?UserRequest)
               (increase (total-cost) 1)))

(:action application-tomcat-mixes-additional-smuggled-http-request-with-user-session-context
  :parameters (?Tomcat - tomcat ?SmuggledRequest - http-request ?UserRequest - http-request ?UserSession - user-session)
  :precondition (and (smuggled-request-ready-for-processing ?SmuggledRequest)
                     (user-request-received-by-tomcat ?Tomcat ?UserRequest)
                     (user-http-request ?UserRequest)
                     (authenticated-user-request ?UserRequest)
                     (request-boundary-confusion ?Tomcat))
  :effect (and (request-context-mixed ?Tomcat ?SmuggledRequest ?UserSession)
               ;(session-hijack-condition ?SmuggledRequest ?UserSession)
               (smuggled-request-with-user-context ?SmuggledRequest ?UserSession)
               (increase (total-cost) 1)))

(:action application-tomcat-executes-additional-smuggled-http-request-hijack-user-session-as-authenticated-user-achieving-elevation-of-privilege
  :parameters (?Application - application ?Tomcat - tomcat ?SmuggledRequest - http-request ?UserSession - user-session ?User - user)
  :precondition (and (smuggled-request-with-user-context ?SmuggledRequest ?UserSession)
                     (smuggling-http-request-hijack  ?SmuggledRequest)
                     ;(session-hijack-condition ?SmuggledRequest ?UserSession)
                     (privilege-escalation-payload ?SmuggledRequest))
  :effect (and (user-session-hijacked ?SmuggledRequest ?UserSession)
               (elevation-of-privilege ?Application)
               (smuggled-request-executed-as-user ?SmuggledRequest ?User)
               (increase (total-cost) 1)))

(:action application-tomcat-returns-response-with-sensitive-resource-to-reverse-proxy
  :parameters (?Application - application ?Tomcat - tomcat ?SmuggledRequest - http-request ?User - user ?UserRequest - http-request ?SensitiveResponse - http-response ?SensitiveResource - sensitive-information ?ReverseProxy - reverse-proxy)
  :precondition (and (smuggled-request-executed-as-user ?SmuggledRequest ?User)
                     (targets-sensitive-resource ?UserRequest ?SensitiveResource)
                     (smuggling-http-request-hijack  ?SmuggledRequest)
                     (user-http-request ?UserRequest)
                     (elevation-of-privilege ?Application)
                     (bond-to-user-account ?User ?SensitiveResource))
  :effect (and (sensitive-response-generated ?Tomcat ?SensitiveResponse)
               (contains-sensitive-resource ?SensitiveResponse ?SensitiveResource)
               (sensitive-response-sent-to-proxy ?SensitiveResponse)
               (increase (total-cost) 1)))

(:action reverse-proxy-forwards-sensitive-resource-to-attacker-through-frontend-connection
  :parameters (?Application - application ?ReverseProxy - reverse-proxy ?SensitiveResponse - http-response ?SensitiveResource - sensitive-information ?Attacker - attacker  ?BackendConnection - tcp-connection)
  :precondition (and (sensitive-response-sent-to-proxy ?SensitiveResponse)
                     (contains-sensitive-resource ?SensitiveResponse ?SensitiveResource)
                     (attacker-connected-to-proxy ?Attacker ?ReverseProxy)
                     (connection-reused ?BackendConnection))
  :effect (and (information-disclosure ?Application)
               (increase (total-cost) 1)))

   

(:action attacker-sends-additional-smuggled-http-request-containing-cache-poisoning-on-existing-frontend-connection-to-reverse-proxy
  :parameters (?Attacker - attacker ?ReverseProxy - reverse-proxy ?SmuggledRequest - http-request ?FrontendConnection - tcp-connection ?CachePoison - cache-poison-payload ?CachedResource - cached-resource)
  :precondition (and (can-send-smuggled-payload ?Attacker)
                     (smuggling-signal-received ?Attacker)
                     (smuggling-http-request-cache-poisoning  ?SmuggledRequest)
                     (frontend-connection-accepted ?ReverseProxy ?FrontendConnection)
                     (cacheable-resource ?CachedResource) )
  :effect (and (smuggled-request-sent ?Attacker ?SmuggledRequest)
               (cache-poisoning-payload ?SmuggledRequest ?CachePoison)
                (privilege-escalation-payload ?SmuggledRequest)
               (attacker-controlled-response-payload ?SmuggledRequest)
               (increase (total-cost) 1)))


(:action user-sends-http-get-request-for-cached-resource
  :parameters (?User - user ?ReverseProxy - reverse-proxy ?UserRequest - http-request ?CachedResource - cached-resource ?UserFrontendConnection - tcp-connection)
  :precondition (and (has-cached-resource ?CachedResource)
                     (user-http-request ?UserRequest)
                     (user-connected-to-proxy ?User ?ReverseProxy)
                     (user-frontend-connection-accepted ?ReverseProxy ?UserFrontendConnection))
  :effect (and (user-request-sent ?User ?UserRequest)
               (targets-cached-resource ?UserRequest ?CachedResource)
               (authenticated-user-request ?UserRequest)
               (increase (total-cost) 1)))


(:action application-tomcat-executes-additional-smuggled-http-request-injects-attacker-controlled-response-into-cache-as-authenticated-user-achieving-elevation-of-privilege
  :parameters (?Application - application ?Tomcat - tomcat ?SmuggledRequest - http-request ?UserSession - user-session ?User - user ?Cache - application-cache)
  :precondition (and (smuggled-request-with-user-context ?SmuggledRequest ?UserSession)
                     (smuggling-http-request-cache-poisoning  ?SmuggledRequest)
                     (attacker-controlled-response-payload ?SmuggledRequest)
                     (has-application-cache ?Application ?Cache))
  :effect (and (cache-injected-with-attacker-content ?Cache ?SmuggledRequest)
               (elevation-of-privilege ?Application)
               (smuggled-request-executed-as-user ?SmuggledRequest ?User)
               (increase (total-cost) 1)))


(:action application-tomcat-serves-response-from-cache-containing-attacker-injected-content-to-reverse-proxy
  :parameters (?Application - application ?Tomcat - tomcat ?SmuggledRequest - http-request ?Cache - application-cache ?PoisonedResponse - http-response ?CachedResource - cached-resource ?ReverseProxy - reverse-proxy )
  :precondition (and (cache-injected-with-attacker-content ?Cache ?SmuggledRequest)
                      (smuggling-http-request-cache-poisoning  ?SmuggledRequest)
                     (elevation-of-privilege ?Application))
  :effect (and (poisoned-response-generated ?Tomcat ?PoisonedResponse)
               (contains-attacker-injected-content ?PoisonedResponse ?Cache)
               (poisoned-response-sent-to-proxy ?PoisonedResponse)
               (increase (total-cost) 1)))


(:action reverse-proxy-forwards-cached-response-to-user-achieving-tampering
  :parameters (?Application - application ?ReverseProxy - reverse-proxy ?PoisonedResponse - http-response ?User - user ?BackendConnection - tcp-connection ?Cache - application-cache)
  :precondition (and (poisoned-response-sent-to-proxy ?PoisonedResponse)
                     (contains-attacker-injected-content ?PoisonedResponse ?Cache)
                     (user-connected-to-proxy ?User ?ReverseProxy)
                     (connection-reused ?BackendConnection))
  :effect (and (tampering ?Application)
               (poisoned-content-delivered-to-user ?User)
               (increase (total-cost) 1)))


)

