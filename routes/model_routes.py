from flask import Blueprint, jsonify, request

# Create an export for app to use blueprints
model_bp = Blueprint('model', __name__)


# Follow the same pattern for the other routes
@model_bp.route('/api/model/stock_price', methods=['GET'])
def get_stock_price():
    stock_ticker = request.args.get('ticker')

    if not stock_ticker:
        return jsonify({'error': 'No stock ticker provided'}), 400

    return jsonify({'stockTicker': stock_ticker, 'price': 100.0})