# ELK installation Ubuntu 18.04

### Elastic search installation 

Java Installation
```
sudo apt update
sudo apt install openjdk-8-jdk
```
Install Nginx
```
sudo apt update
sudo apt install nginx
sudo ufw allow 'Nginx HTTP'
```

Elastic Search
```
sudo apt install apt-transport-https
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-7.9.2-amd64.deb
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-7.9.2-amd64.deb.sha512
shasum -a 512 -c elasticsearch-7.9.2-amd64.deb.sha512 
sudo dpkg -i elasticsearch-7.9.2-amd64.deb
```

Start Elasticsearch Service
```
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch.service
sudo systemctl start elasticsearch.service
```

Test
```
curl localhost:9200
```

Allow Remote Access
```
sudo vim /etc/elasticsearch/elasticsearch.yml
```

Insert the following:
```
transport.host: localhost
transport.tcp.port: 9300
http.port: 9200
network.host: 0.0.0.0
```

Restart service
```
sudo systemctl restart elasticsearch.service
```

### Kibana installation
```
wget https://artifacts.elastic.co/downloads/kibana/kibana-7.9.2-amd64.deb
wget https://artifacts.elastic.co/downloads/kibana/kibana-7.9.2-amd64.deb.sha512
sudo dpkg -i kibana-7.9.2-amd64.deb
```

Enable
```
sudo systemctl enable kibana
sudo systemctl start kibana
```

Create User password
```
echo "kibanaadmin:`openssl passwd -apr1`" | sudo tee -a /etc/nginx/htpasswd.users
```

Modify nginx configuration
```
sudo nano /etc/nginx/sites-available/sunserver.site
```

Insert:
```
server {

        server_name sunserver.site elk.sunserver.site;

        auth_basic "Restricted Access";
        auth_basic_user_file /etc/nginx/htpasswd.users;

        location / {
        proxy_pass http://localhost:5601;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        }

    listen [::]:443 ssl ipv6only=on; # managed by Certbot
    listen [::]:443 ssl ipv6only=on; # managed by Certbot
    listen 443 ssl; # managed by Certbot
    ssl_certificate /etc/letsencrypt/live/sunserver.site/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/sunserver.site/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot


}
server {
    if ($host = elk.sunserver.site) {
        return 301 https://$host$request_uri;
    } # managed by Certbot


    if ($host = sunserver.site) {
        return 301 https://$host$request_uri;
    } # managed by Certbot


        listen 80;
listen [::]:80;

        server_name sunserver.site elk.sunserver.site;
    return 404; # managed by Certbot


}
```

Create simbolic link to sites-enabled

```
sudo ln -s /etc/nginx/sites-available/sunserver.site /etc/nginx/sites-enabled/sunserver.site
```

Check errors
```
sudo nginx -t
```

Restart nginx 
```
sudo systemctl restart nginx
```

Enable firewall
```
sudo ufw allow 'Nginx Full'
```

Installing and Configuring Logstash
Although it’s possible for Beats to send data directly to the Elasticsearch database, we recommend using Logstash to process the data. This will allow you to collect data from different sources, transform it into a common format, and export it to another database.


```

```
