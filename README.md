## How to run the application?
- **Ensure JDK 17 or a later version installed.** This application uses Java records, a feature first supported in 
  Java 17 (the initial LTS version to include it). If you haven't installed it yet, follow 
  [this link](#how-to-install-jdk-17-or-a-later-version) for installation instruction.
- If you prefer running the application in docker, ensure Docker Desktop is installed.
- To start the application, navigate to the project root directory and run `./mvnw spring-boot:run` in your terminal. 
  This will launch the application at [http://localhost:8080](http://localhost:8080)
- Alternatively, to run the application in docker, execute: 
  ```
  ./mvnw spring-boot:build-image && docker run -p 8080:8080 rogertangdeqiang/cyberelay-oauth2:latest
  ```
- The application comes with two pre-configured user accounts:
  - Username/Password: `user/password`
  - Username/Password: `admin/admin`
- TO start `oidc-tester`, create or update `oidc-tester/src/oidc-config.json` file with the following content: 
  ```json
  {
    "redirect_uri": "http://localhost:3000/oauth/callback",
    "oidc_server": "http://localhost:8080/"
  }
  ```
- Follow the `oidc-tester` instructions to launch the tester application, then navigate to 
  [http://localhost:3000](http://localhost:3000) to run the test cases. If prompted for username/password, use 
  the pre-configured username/passwords mentioned above.

## What is Cyberelay?
- **Cyberelay** was a name I created for my Web Portal Server project about 20 years ago, though the project 
  itself never gained traction. The main outcome of this endeavor was registering the domains `cyberelay.com` and 
  `cyberelay.org`. Over the years, I've primarily used Cyberelay for Java package naming in my hobby projects.  

## How to Review the Code?
- This application is a Spring Boot project. Refer to [this document](doc/references.md) for details on the tech stack 
  being used.
- I would start by looking at the controllers, which implement the OAuth2 REST APIs. The controller names are 
  self-explanary, with each one handling a specific OAuth2 endpoint.
- Next, review the `AppConfig` class, which serves as the factory for all service components used by the controllers,
  including:
  - Public/private key pairs
  - Initiation of Pre-configured user account
  - JWK source
  - Token generators
  - Authorization service
  - User details service
  - Data access objects (DAO). (_Note: The application uses an embedded H2 database for persistence. See [How to access
    H2 admin console](#how-to-access-h2-database-admin-console) for more details._)

## Things Worth-mentioning
- `oidc-tester` does not supply a `client_id`, but the Spring Security library used by this application requires 
  a `client_id` to be present. To bridge this gap, a default client is generated, and this default `client_id` is 
  provided whenever the Spring Security library requires it. 
- Although managing users & credentials is optional according to the requirement document, this application includes 
  user and credential management using an H2 database to adhere more closely to the OAuth2 standard.
- While the login and consent pages are optional per the requirement document, this application has implemented them
  to align with the OAuth2 standard.
- The project was initiated using [Spring Initializr](https://start.spring.io/). The project evolution can be tracked
  by reviewing the Git repository logs.

## Misc

#### How to Install JDK 17 or a Later Version?
- You can follow the instructions on the [SDKMAN! website](https://sdkman.io/) to install the JDK.

#### How to Access H2 Database Admin Console?
- You can access the database at [http://localhost:8080/h2-console](http://localhost:8080/h2-console) once the 
  application is running. Use the following credentials to login
  - **JDBC URL**: `jdbc:h2:mem:testdb`
  - **Username**: `sa`
  - **Password**: `password`