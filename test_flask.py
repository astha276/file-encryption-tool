from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello():
    return '''
    <h1>🎉 Flask is Working!</h1>
    <p>Your File Encryption Tool web demo is ready!</p>
    <a href="/demo">View Demo</a>
    '''

@app.route('/demo')
def demo():
    return '''
    <h2>🔐 File Encryption Tool Demo</h2>
    <p>This confirms your Flask setup is working correctly!</p>
    <a href="/">Back to Home</a>
    '''

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
