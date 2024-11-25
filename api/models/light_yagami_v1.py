import yfinance as yf
from sklearn.linear_model import LinearRegression
from sklearn.model_selection import train_test_split
import numpy as np


class StockAnalyzer:
    def __init__(self):
        self.history_data = None

    def get_summary_info(self, ticker_symbol):
        """Returns a summary of the stock's basic info."""
        stock = yf.Ticker(ticker_symbol)
        return stock.info

    def fetch_history(self, ticker_symbol, period='1y', interval='1d'):
        """Fetches historical stock data and summary data."""
        stock = yf.Ticker(ticker_symbol)
        self.history_data = stock.history(period=period, interval=interval)

        # Add stock summary info like P/E ratio
        info = stock.info
        self.history_data['PE_Ratio'] = info.get('trailingPE', np.nan)  # Adding P/E ratio

        return self.history_data

    def calculate_moving_average(self, window=20):
        """Calculates the moving average for the specified window size."""
        if self.history_data is None:
            raise ValueError("Historical data not available. Fetch history first.")
        self.history_data[f'SMA_{window}'] = self.history_data['Close'].rolling(window=window).mean()
        return self.history_data[[f'SMA_{window}']]

    def calculate_rsi(self,window=14):
        """Calculates the Relative Strength Index (RSI) for the specified window size."""
        delta = self.history_data['Close'].diff(1)
        gain = (delta.where(delta > 0, 0)).rolling(window=window).mean()
        loss = (-delta.where(delta < 0, 0)).rolling(window=window).mean()

        rs = gain / loss
        self.history_data['RSI'] = 100 - (100 / (1 + rs))
        return self.history_data['RSI']

    @staticmethod
    def static_calculate_rsi(ticker, window=14):
        """Calculates the Relative Strength Index (RSI) for the specified window size."""
        stock = yf.Ticker(ticker)
        history_data = stock.history(period='1y', interval='1d')
        delta = history_data['Close'].diff(1)
        gain = (delta.where(delta > 0, 0)).rolling(window=window).mean()
        loss = (-delta.where(delta < 0, 0)).rolling(window=window).mean()

        rs = gain / loss
        history_data['RSI'] = 100 - (100 / (1 + rs))

        rsi_dict = {str(date): value for date, value in history_data['RSI'].dropna().items()}
        return rsi_dict

    def prepare_features(self):
        """Prepare features and target variable for modeling."""
        if self.history_data is None:
            raise ValueError("Historical data not available. Fetch history first.")

        # Calculate additional indicators
        self.calculate_moving_average(window=20)  # 20-day SMA
        self.calculate_moving_average(window=50)  # 50-day SMA
        self.calculate_rsi(window=14)  # 14-day RSI

        # Drop NaN values that result from indicator calculations
        self.history_data.dropna(inplace=True)

        # Select features for regression
        X = self.history_data[['SMA_20', 'SMA_50', 'RSI', 'PE_Ratio', 'Volume']]
        y = self.history_data['Close']  # Target variable

        return X, y


class StockPredictor:
    def __init__(self):
        self.model = LinearRegression()
        self.X_test = None
        self.y_test = None

    def train(self, X, y):
        """Trains the linear regression model."""
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=0)

        # Fit the model
        self.model.fit(X_train, y_train)

        # Store test data for evaluation
        self.X_test, self.y_test = X_test, y_test

    def predict(self, X):
        """Predicts using the trained model."""
        return self.model.predict(X)


# Example usage
if __name__ == "__main__":
    ticker_symbol = 'GOOG'
    stock_analyzer = StockAnalyzer()
    stock_analyzer.fetch_history(ticker_symbol)
    X, y = stock_analyzer.prepare_features()

    stock_predictor = StockPredictor()
    stock_predictor.train(X, y)
    last_day_info = X.iloc[[-1]]  # Extract the last row of feature data
    prediction = stock_predictor.predict(last_day_info)
    print(f"Predicted closing price for {ticker_symbol}: {prediction[0]}")
