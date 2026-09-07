from locust import HttpUser, task, between


class GraphRAGUser(HttpUser):
    wait_time = between(1, 3)

    def on_start(self):
        resp = self.client.post(
            "/api/v1/auth/login",
            json={"username": "analyst", "password": "SecureAnalyst2024!"},
        )
        if resp.status_code == 200:
            token = resp.json().get("access_token")
            self.headers = {"Authorization": f"Bearer {token}"}
        else:
            self.headers = {}

    @task(3)
    def test_query_investigation(self):
        self.client.post(
            "/api/v1/query",
            json={"query": "What malware does PHANTOM DRAGON use?"},
            headers=self.headers,
        )

    @task(1)
    def test_health_probe(self):
        self.client.get("/health")
