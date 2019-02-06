# mikrotik-blocklist
Create blocklist for Mikrotik ROS. Tested on Mikrotik RB4011, RB3011, HexS. Consumes about 100 MB of ram. 

There are two scripts, one to fetch data and store in mysql databasei, fetch.pl. The other script (export.pl) gets data from database and makes a output file in ROS format.

Currently the export.pl fetches the blacklisted ip stored in the database the last 3 days. Modify this to whatever you find useful. Currently the output consists of around 80 000 unique addresses.


The database needs to have 5 fields:

Fieldname:	Type		Allow nulls?	Key	Default value	Extras

address_type	varchar(8)	No		Primary	NULL		

address_value	varchar(20)	No		Primary	NULL

created		datetime	Yes		None	NULL

updated		timestamp	No		None	CURRENT_TIMESTAMP on update CURRENT_TIMESTAMP

comment		tinytext	Yes		None	NULL

The schema.sql can be used to populate your database.

