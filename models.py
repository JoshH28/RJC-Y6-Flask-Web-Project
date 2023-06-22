from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import String, ForeignKey, Float, Integer
from flask_login import UserMixin
from typing import List

class Base(DeclarativeBase):
    pass

class User(Base, UserMixin):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    user_email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    pass_hash: Mapped[str] = mapped_column(String, nullable=False)
    confirmed: Mapped[bool] = mapped_column(nullable=False, default=False)
    salt: Mapped[str] = mapped_column(String(64), nullable=False)
    salt2: Mapped[str] = mapped_column(String(64), nullable=False)
    salt3: Mapped[str] = mapped_column(String(64), nullable=False)
    salt4: Mapped[str] = mapped_column(String(64), nullable=False)
    salt5: Mapped[str] = mapped_column(String(64), nullable=False)

    current_order: Mapped['Order'] = relationship(back_populates="user", lazy=True)

class Order(Base):
    __tablename__ = "orders"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id")) 
    user: Mapped['User'] = relationship(back_populates="current_order", lazy=True)

    food_orders: Mapped[str] = mapped_column(String)
    '''
        DO NOT USE \n OR | IN THE NAMES OR ANYTHING
        Separated by \n
        quantity|food name|cost for 1 item|stall name
    '''
    

class Stall(Base):
    __tablename__ = "stalls"
    id: Mapped[int] = mapped_column(primary_key=True)
    stall_name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    image_directory: Mapped[str] = mapped_column(String(300))

    food_items: Mapped[List["Food"]] = relationship(back_populates="stall", lazy=True)
    
class Food(Base):
    __tablename__ = "foods"
    id: Mapped[int] = mapped_column(primary_key=True)
    food_name: Mapped[str] = mapped_column(String(100), nullable=False)
    cost: Mapped[float] = mapped_column(Float)
    image_directory: Mapped[str] = mapped_column(String(300))

    stall_id: Mapped[int] = mapped_column(ForeignKey("stalls.id"))
    stall: Mapped['Stall'] = relationship(back_populates="food_items", lazy=True)