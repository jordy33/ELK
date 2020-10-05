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

![title](logstash.png)

Create a configuration file called 02-beats-input.conf where you will set up your Filebeat input:
```
sudo vim /etc/logstash/conf.d/02-beats-input.conf
```
Insert the following input configuration. This specifies a beats input that will listen on TCP port 5044.
```
/etc/logstash/conf.d/02-beats-input.conf
input {
  beats {
    port => 5044
  }
}
```
Save and close the file. Next, create a configuration file called 10-syslog-filter.conf, where we will add a filter for system logs, also known as syslogs:

```
sudo vim /etc/logstash/conf.d/10-syslog-filter.conf
```

insert the following filter :  This example system logs configuration was taken from official Elastic documentation. This filter is used to parse incoming system logs to make them structured and usable by the predefined Kibana dashboards:
```
filter {
  if [fileset][module] == "system" {
    if [fileset][name] == "auth" {
      grok {
        match => { "message" => ["%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sshd(?:\[%{POSINT:[system][auth][pid]}\])?: %{DATA:[system][auth][ssh][event]} %{DATA:[system][auth][ssh][method]} for (invalid user )?%{DATA:[system][auth][user]} from %{IPORHOST:[system][auth][ssh][ip]} port %{NUMBER:[system][auth][ssh][port]} ssh2(: %{GREEDYDATA:[system][auth][ssh][signature]})?",
                  "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sshd(?:\[%{POSINT:[system][auth][pid]}\])?: %{DATA:[system][auth][ssh][event]} user %{DATA:[system][auth][user]} from %{IPORHOST:[system][auth][ssh][ip]}",
                  "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sshd(?:\[%{POSINT:[system][auth][pid]}\])?: Did not receive identification string from %{IPORHOST:[system][auth][ssh][dropped_ip]}",
                  "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sudo(?:\[%{POSINT:[system][auth][pid]}\])?: \s*%{DATA:[system][auth][user]} :( %{DATA:[system][auth][sudo][error]} ;)? TTY=%{DATA:[system][auth][sudo][tty]} ; PWD=%{DATA:[system][auth][sudo][pwd]} ; USER=%{DATA:[system][auth][sudo][user]} ; COMMAND=%{GREEDYDATA:[system][auth][sudo][command]}",
                  "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} groupadd(?:\[%{POSINT:[system][auth][pid]}\])?: new group: name=%{DATA:system.auth.groupadd.name}, GID=%{NUMBER:system.auth.groupadd.gid}",
                  "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} useradd(?:\[%{POSINT:[system][auth][pid]}\])?: new user: name=%{DATA:[system][auth][user][add][name]}, UID=%{NUMBER:[system][auth][user][add][uid]}, GID=%{NUMBER:[system][auth][user][add][gid]}, home=%{DATA:[system][auth][user][add][home]}, shell=%{DATA:[system][auth][user][add][shell]}$",
                  "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} %{DATA:[system][auth][program]}(?:\[%{POSINT:[system][auth][pid]}\])?: %{GREEDYMULTILINE:[system][auth][message]}"] }
        pattern_definitions => {
          "GREEDYMULTILINE"=> "(.|\n)*"
        }
        remove_field => "message"
      }
      date {
        match => [ "[system][auth][timestamp]", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
      }
      geoip {
        source => "[system][auth][ssh][ip]"
        target => "[system][auth][ssh][geoip]"
      }
    }
    else if [fileset][name] == "syslog" {
      grok {
        match => { "message" => ["%{SYSLOGTIMESTAMP:[system][syslog][timestamp]} %{SYSLOGHOST:[system][syslog][hostname]} %{DATA:[system][syslog][program]}(?:\[%{POSINT:[system][syslog][pid]}\])?: %{GREEDYMULTILINE:[system][syslog][message]}"] }
        pattern_definitions => { "GREEDYMULTILINE" => "(.|\n)*" }
        remove_field => "message"
      }
      date {
        match => [ "[system][syslog][timestamp]", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
      }
    }
  }
}
```

Lastly, create a configuration file called 30-elasticsearch-output.conf:
```
sudo vim /etc/logstash/conf.d/30-elasticsearch-output.conf
```

insert the following
```
output {
  elasticsearch {
    hosts => ["localhost:9200"]
    manage_template => false
    index => "%{[@metadata][beat]}-%{[@metadata][version]}-%{+YYYY.MM.dd}"
  }
}
```
