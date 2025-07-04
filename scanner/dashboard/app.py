import dash
from dash import dcc, html
import plotly.express as px
from scanner import AdvancedNetworkScanner

app = dash.Dash(__name__)

scanner = AdvancedNetworkScanner()

app.layout = html.Div([
    html.H1("Network Dashboard"),
    dcc.Graph(id='device-map'),
    dcc.Interval(id='interval', interval=5000)
])

@app.callback(
    dash.dependencies.Output('device-map', 'figure'),
    [dash.dependencies.Input('interval', 'n_intervals')]
)
def update_graph(n):
    devices = scanner.scan("192.168.1.0/24")
    return px.scatter(
        devices, 
        x='ip', 
        y='type',
        color='os',
        size='vulns_count'
    )

if __name__ == '__main__':
    app.run_server(debug=True)