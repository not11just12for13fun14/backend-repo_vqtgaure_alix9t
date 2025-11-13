"""
Database Schemas for the Game Store application

Each Pydantic model corresponds to a MongoDB collection (lowercased class name)
- User -> user
- Game -> game
- Order -> order
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Unique email address")
    hashed_password: str = Field(..., description="BCrypt hashed password")
    is_admin: bool = Field(False, description="Admin access flag")

class Game(BaseModel):
    title: str = Field(..., description="Game title")
    description: Optional[str] = Field(None, description="Detailed description")
    price: float = Field(..., ge=0, description="Price in local currency")
    platform: str = Field(..., description="Platform: PC or Mobile")
    category: Optional[str] = Field(None, description="Genre or category")
    images: List[str] = Field(default_factory=list, description="Image URLs")
    is_active: bool = Field(True, description="Visible in store")

class Order(BaseModel):
    user_id: Optional[str] = Field(None, description="Ordering user id (if logged in)")
    game_id: str = Field(..., description="Purchased game id")
    email_for_delivery: EmailStr = Field(..., description="Email to receive the game/key")
    nagad_number: str = Field(..., description="Nagad sender mobile number")
    transaction_id: str = Field(..., description="Nagad transaction ID")
    status: str = Field("pending", description="pending | completed | canceled")
