import streamlit as st
import pandas as pd
import altair as alt

def render_timeline(df: pd.DataFrame) -> None:
    df = df.copy()
    df['ctime'] = pd.to_datetime(df['ctime'])
    df['relpath'] = df.get('relpath', df.get('filename', '<unknown>'))

    chart = (
        alt.Chart(df)
           .mark_tick(thickness=2, size=20)
           .encode(
               x=alt.X(
                   'ctime:T',
                   title='Timestamp',
                   axis=alt.Axis(
                       format='%Y-%m-%d %H:%M',    # show full date + hour:minute
                       tickCount='hour',           # place one tick per hour (or use an int)
                       labelAngle=-45,             # slanted labels to avoid overlap
                       labelOverlap='greedy'       # force Altair to drop overlapping labels
                   )
               ),
               y=alt.Y('category:N', title=None, sort=list(df['category'].unique())),
               color=alt.Color('category:N', legend=None),
               tooltip=[
                   alt.Tooltip('relpath:N', title='File'),
                   alt.Tooltip('ctime:T', title='Created'),
                   alt.Tooltip('category:N')
               ]
           )
           .properties(
               title='File Creation Timeline by Category',
               height=300,
               width=800
           )
           .interactive()
    )

    st.altair_chart(chart, use_container_width=True)
