# mikrotik-blocklist
Create blocklist for Mikrotik ROS

There are two scripts, one to fetch data and store in mysql database. The other gets data from database and makes a output file in ROS format.


The database needs to have 5 fields:

Fieldname:	Type		Allow nulls?	Key	Default value	Extras

address_type	varchar(8)	No		Primary	NULL		

address_value	varchar(20)	No		Primary	NULL

created		datetime	Yes		None	NULL

updated		timestamp	No		None	CURRENT_TIMESTAMP on update CURRENT_TIMESTAMP

comment		tinytext	Yes		None	NULL



