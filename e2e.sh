#!/bin/bash -e

BASE_URL=http://localhost:8080
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjc5NTUxODc3NDJ9.l5PJbjxZJnbt1wI3qRMlMgkJVRKxeTokD3K_AM6ZxCs"

# Start the application
docker compose down
docker compose up -d --build
while ! curl -f $BASE_URL/; do sleep 1; done

# / redirect to login page
res=$(curl $BASE_URL)
if [[ !("$res" =~ "<title>Login</title>") ]]; then
  echo "Test failed: / redirect to login page"
  echo $res
  exit 1
fi

# login
status=$(curl -X POST $BASE_URL/login --data-urlencode "password=1234&redirect_to=$BASE_URL" -w "%{http_code}")
if [[ $status != 303 ]]; then
  echo "Test failed: login"
  echo "status=$status (expected 303)"
  exit 1
fi

# / not redirect to login page after login
res=$(curl $BASE_URL -H "cookie: token=$TOKEN")
if [[ !("$res" =~ "# rust_jwt_auth_with_login_page") ]]; then
  echo "Test failed: / not redirect to login page after login"
  echo $res
  exit 1
fi
