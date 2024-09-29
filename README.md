## How to run the application

**Note:** Below instruction assumes you are at the project root directory.
### Run from Terminal
```bash
./mvnw spring-boot:run
```

### Run in Docker
```bash
# build docker image
./mvnw spring-boot:build-image

# run application in docker
docker run -p 8080:8080 rogertangdeqiang/cyberelay-oauth2:latest
```

## How to access H2 database admin console
- Visit [http://localhost:8080/h2-console](http://localhost:8080/h2-console)
- Use below info to login
  - **JDBC URL**: jdbc:h2:mem:testdb
  - **Username**: sa
  - **Password**: password