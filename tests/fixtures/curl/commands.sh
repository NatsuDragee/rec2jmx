# flow: Login
curl 'https://api.example.test/api/v1/login' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  --data-raw '{"username":"test.user","password":"Sup3rS3cret!"}' \
  --compressed
# flow: Browse catalog
curl -s "https://api.example.test/api/v1/products?category=books&page=2" -H "Authorization: Bearer tok_live_ABCDEF1234567890"
curl -X DELETE https://api.example.test/api/v1/cart/items/77 -H $'X-Note: line\tone'
# flow: Upload avatar
curl -F 'name=avatar' -F 'file=@/home/user/me.png;type=image/png' https://api.example.test/api/v1/profile/avatar
curl -u test.user:pa55word -d 'a=1' -d 'b=two words' https://legacy.example.test:8443/form.php
