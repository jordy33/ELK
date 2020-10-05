# ELK

### Elastic search installation Ubuntu

Java Installation
```
sudo apt update
sudo apt install openjdk-8-jdk
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
