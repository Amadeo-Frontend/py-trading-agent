from dotenv import load_dotenv
import os

load_dotenv()

class Settings:
    GOOGLE_API_KEY: str = os.getenv("GOOGLE_API_KEY", "")
    POLYGON_API_KEY: str = os.getenv("POLYGON_API_KEY", "")

    # Ex: "http://localhost:3000,https://meu-front.vercel.app"
    FRONTEND_ORIGINS_RAW: str = os.getenv("FRONTEND_ORIGINS", "http://localhost:3000")

    @property
    def frontend_origins(self) -> list[str]:
        return [o.strip() for o in self.FRONTEND_ORIGINS_RAW.split(",") if o.strip()]

settings = Settings()
