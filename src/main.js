import React from 'react';
import { Router, Route, browserHistory, IndexRoute } from 'react-router';
import Root from './Components/Root';
import Servers from './Components/Servers';
import Users from './Components/Users';
import Groups from './Components/Groups';
import Nomatch from './Components/Nomatch';

class Main extends React.Component {

    render() {
        return (
            <Router history={browserHistory}>
                <Route path={"/"} component={Root} >
                    <IndexRoute component={Servers} />
                    <Route path={"users"} component={Users} />
                    <Route path={"servers"} component={Servers} />
                    <Route path={"groups"} component={Groups} />
                </Route>
                <Route path={"*"} component={Nomatch} />
            </Router>
        )
    }
}

export default Main;