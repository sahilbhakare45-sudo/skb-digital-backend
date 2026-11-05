from pathlib import Path
from sqlalchemy import (
    create_engine,
    Column,
    String,
    Integer,
    Boolean,
    DateTime,
    inspect,
    text
)
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime, timezone


BASE_DIR = Path(__file__).resolve().parent

DATABASE_URL = f"sqlite:///{BASE_DIR / 'skb_digital.db'}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


class FileRecord(Base):
    __tablename__ = "files"

    id = Column(String, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    stored_name = Column(String, nullable=False)
    file_size = Column(Integer, default=0)

    # NEW CATEGORY FIELD
    category = Column(
        String,
        nullable=False,
        default="all-resources",
        server_default="all-resources"
    )

    password_hash = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)

    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc)
    )


def create_database():

    # Create tables if they do not exist
    Base.metadata.create_all(bind=engine)

    # Safely add category to an existing database
    inspector = inspect(engine)

    columns = [
        column["name"]
        for column in inspector.get_columns("files")
    ]

    if "category" not in columns:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "ALTER TABLE files "
                    "ADD COLUMN category VARCHAR "
                    "NOT NULL DEFAULT 'all-resources'"
                )
            )