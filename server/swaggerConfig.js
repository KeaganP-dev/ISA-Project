const swaggerJsDoc = require('swagger-jsdoc');

const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'API Documentation',
            version: '1.0.0',
            description: 'API documentation for user authentication and API consumption service',
        },
        servers: [
            {
                url: 'https://www.keaganpurtell.com/v1',
                description: 'Development server',
            },
        ],
    },
    apis: ['./server.js'], // Path to your server file
};

const swaggerDocs = swaggerJsDoc(swaggerOptions);

module.exports = swaggerDocs;
