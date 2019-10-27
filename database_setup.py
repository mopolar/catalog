#!/usr/bin/env python3
# Module to set up database.

from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


#Class to create the table for users
class User(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


#Class to create the table for leagues 
class League(Base):
    __tablename__ = "league"

    id = Column(Integer, primary_key=True)
    name = Column(String(50), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    #Return object data in easily serializeable format
    @property
    def serialize(self):
        return {
            'id': self.id,
            'country': self.name,
            'user_id': self.user_id
        }


#Class to create the table for clubs 
class Club(Base):
    __tablename__ = "club"

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    description = Column(String(250))
    league_id = Column(Integer, ForeignKey('league.id'))
    league = relationship(League)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    #Return object data in easily serializeable format
    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.country,
            'description': self.description,
            'league_id': self.league_id,
            'user_id': self.user_id
        }

engine = create_engine('engine = create_engine('postgresql://catalog:polar@localhost/catalog')')
Base.metadata.create_all(engine)