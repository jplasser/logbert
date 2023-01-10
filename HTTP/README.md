POST https://idp.services.com/as/token.oauth2 HTTP/1.1 | Connection: keep-alive | Content-Type: application/x-www-form-urlencoded | charset: utf-8 | Authorization: | Content-Length: 442 | Host: idp.services.com | User-Agent: default |  | grant_type=password&username=ELOOE01V9V100267&password=%7B%22user_agent%22%3A%22Dalvik%2F2.1.0+%28Linux%3B+U%3B+Android+6.0.1%3B+SM-G930F+Build%2FMMB29K%29%22%2C+%22anmeldeart%22%3A%22loginDevice%22%2C+%22device_id%22%3A%227845540b-e123-4872-aabc-88505b7a1f5b%22%2C+%22device_secret%22%3A%22MEYCIQCBv%2BqN75TiBAYpR5a6H4t%2Be7CNn%2BlAtpjWYiAkqyeG7QIhAK5ZPrNWtUFSa8KJe6FLRUFwNyP4TwNL4EcrXsZ%2Bbv0G%22%7D&client_id=DRB-APP&validator_id=DRBAPPPCV |

GET https://app.services.com/api/app-services-login/login-ui-services/rest/login/backendstate HTTP/1.1 | Connection: keep-alive | Content-Type: application/json | charset: utf-8 | Authorization: Bearer | Host: app.services.com | User-Agent: default

POST https://idp.services.com/as/token.oauth2 HTTP/1.1 | Connection: keep-alive | Content-Type: application/x-www-form-urlencoded | charset: utf-8 | Authorization: | Content-Length: 440 | Host: idp.services.com | User-Agent: default |  | grant_type=password&username=ELOOE01V7V100273&password=%7B%22user_agent%22%3A%22Dalvik%2F2.1.0+%28Linux%3B+U%3B+Android+6.0.1%3B+SM-G930F+Build%2FMMB29K%29%22%2C+%22anmeldeart%22%3A%22loginDevice%22%2C+%22device_id%22%3A%2240860239-167b-41b2-a361-e83d2a3efd58%22%2C+%22device_secret%22%3A%22MEYCIQD6iwSbZgayH0fMU2CKk%2F4yC9uuQjkomxm%2FOXlmfk1hqQIhANDYb1Pvz7FbEg9w5KZD0ydLXtqaklwoTOJo7r8%2BtQuT%22%7D&client_id=DRB-APP&validator_id=DRBAPPPCV

POST https://idp.services.com/as/token.oauth2 HTTP/1.1 | Connection: keep-alive | Content-Type: application/x-www-form-urlencoded | charset: utf-8 | Authorization: | Content-Length: 438 | Host: idp.services.com | User-Agent: default |  | grant_type=password&username=ELOOE01V0V100268&password=%7B%22user_agent%22%3A%22Dalvik%2F2.1.0+%28Linux%3B+U%3B+Android+6.0.1%3B+SM-G930F+Build%2FMMB29K%29%22%2C+%22anmeldeart%22%3A%22loginDevice%22%2C+%22device_id%22%3A%228046c2ce-495d-4e07-87c1-9187eac74a3e%22%2C+%22device_secret%22%3A%22MEUCIBUGpZMMSPpGrdnCDdCHK%2B4LF29Vh6ZNTW0lAhzJoIlgAiEA5TLK1VjPu6Nmt5KBEdsubjqQMfIhMsrMSRBTtVOjbcg%3D%22%7D&client_id=DRB-APP&validator_id=DRBAPPPCV

GET https://app.services.com/api/app-services-login/login-ui-services/rest/login/backendstate HTTP/1.1 | Connection: keep-alive | Content-Type: application/json | charset: utf-8 | Authorization: Bearer | Host: app.services.com | User-Agent: default

GET https://app.services.com/api/app-services-login/login-ui-services/rest/login/backendstate HTTP/1.1 | Connection: keep-alive | Content-Type: application/json | charset: utf-8 | Authorization: Bearer | Host: app.services.com | User-Agent: default

PUT https://app.services.com/api/app-services-login/login-ui-services/rest/login/authentications HTTP/1.1 | Connection: keep-alive | Content-Type: application/json | charset: utf-8 | Authorization: Bearer | Content-Length: 156 | Host: app.services.com | User-Agent: default |  | { |   "verfuegerId": "ELOOE01V7V100273", |   "kobilDeviceId": null, |   "deviceId": "40860239-167b-41b2-a361-e83d2a3efd58", |   "salt": "10.11.2022 17:01:24" | }

---
log_format = '<Date> <Time> <Method> <URI> HTTP/1.1 <Content-Type> <Authorization> <Content-Length> <Host> <User Agent> <Payload Content>'  # Web Requests log format

<Date> date
<Time> time
<Method> method like GET, PUT, POST etc.
<URI> URI like https://app.services.com/api/app-services-login/login-ui-services/rest/login/authentications
<Content-Type> content type as e.g. application/json 
<Authorization> auth method and bearer
<Content-Length> content length
<Host> host, which is redundant as already in the URI
<User Agent> the browser id
<Payload Content> the payload for the request

optional:
<Response Status> status code like 200, 204, 404 etc.
<Length Response> length of the response
<Referer> referer