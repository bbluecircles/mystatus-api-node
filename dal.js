// Get the client
const mysql = require('mysql2');
require('dotenv').config()

function getConnection() {
    return mysql.createConnection({
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        port: process.env.DB_PORT
    })
}

function readActions(username) {
    try {
        console.log(`USERNAME: ${username}`)
        const connection = getConnection();
        ///connection.connect();
        connection.query(`call get_actions_with_weights('${username}')`, function(error, result) {
            if (error) throw error;
            console.log(JSON.stringify(result));
        });
        //connection.end();

    } catch(e) {
        console.error(e)
    }
}

module.exports = { readActions }