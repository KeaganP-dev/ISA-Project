from flask import Blueprint, request, jsonify
from models.light_yagami_v1 import StockPredictor, StockAnalyzer

stock_bp = Blueprint('stock', __name__)
analyzer = StockAnalyzer()


@stock_bp.route('/predict', methods=['GET'])
def predict_price():
    ticker_symbol = request.args.get('symbol')
    if not ticker_symbol:
        return jsonify({"error": "Ticker symbol is required"}), 400

    # Step 1: Initialize the StockAnalyzer and fetch/prepare data
    analyzer = StockAnalyzer()
    try:
        analyzer.fetch_history(ticker_symbol)
        X, y = analyzer.prepare_features()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    # Step 2: Initialize the StockPredictor, train the model, and make a prediction for the last day
    predictor = StockPredictor()
    predictor.train(X, y)
    last_day_info = X.iloc[[-1]]  # Extract the last row of feature data
    last_day_prediction = predictor.predict(last_day_info)

    return jsonify({"symbol": ticker_symbol, "predicted_price": last_day_prediction[0]})


@stock_bp.route('/summary-info', methods=['GET'])
def summary_info():
    ticker = request.args.get('ticker')

    if not ticker:
        return jsonify({'error': 'Ticker symbol is required'}), 400

    try:
        summary = analyzer.get_summary_info(ticker)
        return jsonify(summary)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@stock_bp.route('/rsi', methods=['GET'])
def summary_info():
    ticker = request.args.get('ticker')

    if not ticker:
        return jsonify({'error': 'Ticker symbol is required'}), 400

    try:
        summary = analyzer.static_calculate_rsi(ticker)
        return jsonify(summary)
    except Exception as e:
        return jsonify({'error': str(e)}), 500