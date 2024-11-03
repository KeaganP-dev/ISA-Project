from flask import Blueprint, request, jsonify
from data_collection.yahoo_finance_data import StockAnalyzer

stock_bp = Blueprint('stock', __name__)
analyzer = StockAnalyzer()


@stock_bp.route('/fetch-history', methods=['GET'])
def fetch_history():
    ticker = request.args.get('ticker')
    period = request.args.get('period', '1y')
    interval = request.args.get('interval', '1d')

    if not ticker:
        return jsonify({'error': 'Ticker symbol is required'}), 400

    try:
        history = analyzer.fetch_history(ticker, period=period, interval=interval)
        return history.to_json()  # Converts the DataFrame to JSON format
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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


@stock_bp.route('/moving-average', methods=['GET'])
def moving_average():
    ticker = request.args.get('ticker')
    window = request.args.get('window', 20, type=int)

    if not ticker:
        return jsonify({'error': 'Ticker symbol is required'}), 400

    try:
        analyzer.fetch_history(ticker)  # Ensure historical data is loaded
        moving_avg = analyzer.calculate_moving_average(window=window)
        return moving_avg.to_json()  # Converts the DataFrame to JSON format
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@stock_bp.route('/max-min-price', methods=['GET'])
def max_min_price():
    ticker = request.args.get('ticker')

    if not ticker:
        return jsonify({'error': 'Ticker symbol is required'}), 400

    try:
        analyzer.fetch_history(ticker)  # Ensure historical data is loaded
        max_min = analyzer.get_max_min_price()
        return jsonify(max_min)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@stock_bp.route('/pe-ratios', methods=['GET'])
def pe_ratios():
    ticker = request.args.get('ticker')

    if not ticker:
        return jsonify({'error': 'Ticker symbol is required'}), 400

    try:
        pe_ratios = analyzer.get_pe_ratios(ticker)
        return jsonify(pe_ratios)
    except Exception as e:
        return jsonify({'error': str(e)}), 500