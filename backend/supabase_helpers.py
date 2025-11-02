from supabase import create_client
from config import SUPABASE_URL, SUPABASE_KEY

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

def supabase_select(table, column=None, operator=None, value=None):
    query = supabase.table(table).select("*")
    if column and operator and value is not None:
        query = query.filter(column, operator, value)
    return query.execute().data

 


def supabase_insert(table, data):
    return supabase.table(table).insert(data).execute().data


def supabase_update(table, id_column, id_value, data):
    return supabase.table(table).update(data).eq(id_column, id_value).execute().data
