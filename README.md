# checkpoint_tpapi_webservice
Web service to clean and check files using checkpoint threat prevention API and as web service python Flask.

1. To deploy the app on Linux follow this tutorial:
https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-xvii-deployment-on-linux

2. To deploy the app on docker follow this tutorial:
https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-xix-deployment-on-docker-containers

Run mysql container
sudo docker run --name mysql -d -e MYSQL_RANDOM_ROOT_PASSWORD=yes \
    -e MYSQL_DATABASE=scrubbing -e MYSQL_USER=scrubbing \
    -e MYSQL_PASSWORD=scrubbing_db_password \
    mysql/mysql-server:5.7
	
	
Run app on docker	
sudo docker run --name scrubbing -d -p 4444:4444 --rm -e SECRET_KEY=my-secret-key --link mysql:dbserver -e DATABASE_URL=mysql+pymysql://scrubbing:scrubbing_db_password@dbserver/scrubbing scrubbing:latest
