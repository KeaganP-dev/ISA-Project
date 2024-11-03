import yfinance as yf


class StockAnalyzer:
    def __init__(self):
        self.history_data = None

    def fetch_history(self, ticker_symbol, period='1y', interval='1d'):
        """Fetches historical stock data."""
        stock = yf.Ticker(ticker_symbol)
        self.history_data = stock.history(period=period, interval=interval)
        return self.history_data

    def get_summary_info(self, ticker_symbol):
        """Returns a summary of the stock's basic info."""
        stock = yf.Ticker(ticker_symbol)
        return stock.info

    def calculate_moving_average(self, window=20):
        """Calculates the moving average for the specified window size."""
        if self.history_data is None:
            raise ValueError("Historical data not available. Fetch history first.")
        self.history_data[f'MA_{window}'] = self.history_data['Close'].rolling(window=window).mean()
        return self.history_data[[f'MA_{window}']]

    def get_max_min_price(self):
        """Finds the maximum and minimum closing prices in the fetched history."""
        if self.history_data is None:
            raise ValueError("Historical data not available. Fetch history first.")
        max_price = self.history_data['Close'].max()
        min_price = self.history_data['Close'].min()
        return {'Max Price': max_price, 'Min Price': min_price}

    def get_day_range(self, ticker_symbol):
        """Returns the day's high and low price."""
        stock = yf.Ticker(ticker_symbol)
        data = stock.history(period='1d')
        return {'Day Low': data['Low'].iloc[-1], 'Day High': data['High'].iloc[-1]}

    def get_52_week_range(self, ticker_symbol):
        """Returns the 52-week high and low price."""
        stock = yf.Ticker(ticker_symbol)
        return {'52 Week Low': stock.info.get('fiftyTwoWeekLow'), '52 Week High': stock.info.get('fiftyTwoWeekHigh')}

    def get_pe_ratios(self, ticker_symbol):
        """Returns all variations of the P/E ratio."""
        stock = yf.Ticker(ticker_symbol)
        return {
            'Trailing P/E': stock.info.get('trailingPE'),
            'Forward P/E': stock.info.get('forwardPE')
        }

    def get_volume_info(self, ticker_symbol):
        """Returns the current day's volume and the average volume over the last 3 months."""
        stock = yf.Ticker(ticker_symbol)
        return {
            'Volume': stock.info.get('volume'),
            'Average Volume (3 months)': stock.info.get('averageVolume')
        }

    def get_market_cap(self, ticker_symbol):
        """Returns the market capitalization."""
        stock = yf.Ticker(ticker_symbol)
        return stock.info.get('marketCap')

    def get_dividend_dates(self, ticker_symbol):
        """Returns the dividend and ex-dividend dates."""
        stock = yf.Ticker(ticker_symbol)
        return {
            'Dividend Date': stock.info.get('dividendDate'),
            'Ex-Dividend Date': stock.info.get('exDividendDate')
        }

    def get_income_statement_info(self, ticker_symbol):
        """Returns income statement metrics."""
        stock = yf.Ticker(ticker_symbol)
        return {
            'Revenue': stock.financials.loc['Total Revenue'].iloc[0],
            'Revenue Per Share': stock.info.get('revenuePerShare'),
            'Quarterly Revenue Growth': stock.info.get('quarterlyRevenueGrowth')
        }

    def get_balance_sheet_info(self, ticker_symbol):
        """Returns balance sheet metrics."""
        stock = yf.Ticker(ticker_symbol)
        return {
            'Total Cash Per Share': stock.info.get('totalCashPerShare'),
            'Total Debt': stock.balance_sheet.loc['Total Debt'].iloc[0],
            'Debt/Equity': stock.info.get('debtToEquity'),
            'Book Value Per Share': stock.info.get('bookValue')
        }

    def get_free_cash_flow(self, ticker_symbol):
        """Returns the free cash flow."""
        stock = yf.Ticker(ticker_symbol)
        return stock.cashflow.loc['Free Cash Flow'].iloc[0]


# Example usage:
if __name__ == "__main__":
    symbol = 'GOOG'  # Example stock ticker
    analyzer = StockAnalyzer()
    print(analyzer.get_day_range(symbol))
    print(analyzer.get_52_week_range(symbol))
    print(analyzer.get_pe_ratios(symbol))
    print(analyzer.get_volume_info(symbol))
    print(analyzer.get_market_cap(symbol))
    print(analyzer.get_dividend_dates(symbol))
    print(analyzer.get_income_statement_info(symbol))
    print(analyzer.get_balance_sheet_info(symbol))
    print(analyzer.get_free_cash_flow(symbol))
