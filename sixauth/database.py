# Made with love by Max

# this file will handle all database related stuff
# all we need is a database connection 

from sqlalchemy import create_engine, Column, Table, MetaData
from sqlalchemy.pool import StaticPool 
        
class Database:
    # first we connect to the database
    def __init__(self, path:str):
        db_path = f'sqlite:///{path}' # define the path to the database
        self.engine = create_engine(db_path, connect_args={'check_same_thread':False}, poolclass=StaticPool) # create a database engine
        self.metadata = MetaData() # metadata for the database
        self.connection = self.engine.connect() # connect to the database
    
    # we need this to save everything to the database when we are done
    def close(self):
        self.connection.commit()
        self.connection.close()
    
    # this allows people to create multiple tables in one db
    def make_table(self, name, columns:list[Column]):
        table = Table(name, self.metadata) # create the table with our metadata
        for column in columns: # then for every column
                table.append_column(column) # append the column to the table
        self.metadata.create_all(self.engine) # then push the table into the db
        return table
    
    # we need to grab things from the database
    def find(self, table:Table, column, key):
        return self.connection.execute(table.select().where(getattr(table.c, column) == key)).fetchone()
    
    # we need to insert things into the database
    def insert(self, table:Table, **values):
        result = self.connection.execute(table.insert().values(**values))
        self.connection.commit()
        return result
    
    # we need to update things in the database
    def update(self, table:Table, column, key, **values):
        result = self.connection.execute(table.update().where(getattr(table.c, column) == key).values(**values))
        self.connection.commit()
        return result
    
    # we need to delete things from the database
    def delete(self, table:Table, column, key):
        result = self.connection.execute(table.delete().where(getattr(table.c, column) == key))
        self.connection.commit()
        return result
    