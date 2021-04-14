import React from "react";
import MaterialTable from 'material-table'
import { useEffect } from 'react'

export default function Table(props) {
    const initial_state = {
      data: props.data,
    };
    const [values, setValues] = React.useState(initial_state);
    useEffect(() => {
      setValues({data: props.data});
    }, [props.data]);

    // console.log("Table", values)
    return (
      <MaterialTable
        title={props.title}
        columns={props.columns}
        data={values.data}        
        options={Object.assign({
          selection: true
        }, props.options)}
        actions={props.actions}
      />
    )
  }
  