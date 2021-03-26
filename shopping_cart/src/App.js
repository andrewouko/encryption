import React from 'react';
import clsx from 'clsx';
import { makeStyles } from '@material-ui/core/styles';
import CssBaseline from '@material-ui/core/CssBaseline';
import Drawer from '@material-ui/core/Drawer';
import Box from '@material-ui/core/Box';
import AppBar from '@material-ui/core/AppBar';
import Toolbar from '@material-ui/core/Toolbar';
import List from '@material-ui/core/List';
import Typography from '@material-ui/core/Typography';
import Divider from '@material-ui/core/Divider';
import IconButton from '@material-ui/core/IconButton';
import Badge from '@material-ui/core/Badge';
import Container from '@material-ui/core/Container';
import Grid from '@material-ui/core/Grid';
import Paper from '@material-ui/core/Paper';
// import Link from '@material-ui/core/Link';
import MenuIcon from '@material-ui/icons/Menu';
import ChevronLeftIcon from '@material-ui/icons/ChevronLeft';
import NotificationsIcon from '@material-ui/icons/Notifications';
import ShoppingCartIcon from '@material-ui/icons/ShoppingCart';
import { ShoppingBasket } from '@material-ui/icons';
import HeadsetMicIcon from '@material-ui/icons/HeadsetMic';
import FaceIcon from '@material-ui/icons/Face';
import AlbumIcon from '@material-ui/icons/Album';
import MusicNoteIcon from '@material-ui/icons/MusicNote';
import { Route, HashRouter, Link } from 'react-router-dom';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItem from '@material-ui/core/ListItem';
import Genres from './Genres';
import Artists from './Artists';
import Albums from './Albums'
import {getCart, removeCartItem} from './CatalogAPI'
import Songs from './Songs';
import Checkout from './Checkout';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import DialogTitle from '@material-ui/core/DialogTitle';
import Button from '@material-ui/core/Button';
import RemoveShoppingCartIcon from '@material-ui/icons/RemoveShoppingCart';
import { useHistory } from "react-router-dom";
function Copyright() {
  return (
    <Typography variant="body2" color="textSecondary" align="center">
      {'Copyright © '}
      <Link color="inherit" href="https://material-ui.com/">
        Shopping cart demo application
      </Link>{' '}
      {new Date().getFullYear()}
      {'.'}
    </Typography>
  );
}

const drawerWidth = 240;

const useStyles = makeStyles((theme) => ({
  root: {
    display: 'flex',
  },
  toolbar: {
    paddingRight: 24, // keep right padding when drawer closed
  },
  toolbarIcon: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'flex-end',
    padding: '0 8px',
    ...theme.mixins.toolbar,
  },
  appBar: {
    zIndex: theme.zIndex.drawer + 1,
    transition: theme.transitions.create(['width', 'margin'], {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.leavingScreen,
    }),
  },
  appBarShift: {
    marginLeft: drawerWidth,
    width: `calc(100% - ${drawerWidth}px)`,
    transition: theme.transitions.create(['width', 'margin'], {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
  },
  menuButton: {
    marginRight: 36,
  },
  menuButtonHidden: {
    display: 'none',
  },
  title: {
    flexGrow: 1,
  },
  drawerPaper: {
    position: 'relative',
    whiteSpace: 'nowrap',
    width: drawerWidth,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
  },
  drawerPaperClose: {
    overflowX: 'hidden',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.leavingScreen,
    }),
    width: theme.spacing(7),
    [theme.breakpoints.up('sm')]: {
      width: theme.spacing(9),
    },
  },
  appBarSpacer: theme.mixins.toolbar,
  content: {
    flexGrow: 1,
    height: '100vh',
    overflow: 'auto',
  },
  container: {
    paddingTop: theme.spacing(4),
    paddingBottom: theme.spacing(4),
  },
  paper: {
    padding: theme.spacing(2),
    display: 'flex',
    overflow: 'auto',
    flexDirection: 'column',
  },
  fixedHeight: {
    height: 240,
  },
  listItem: {
    padding: theme.spacing(1, 0),
  },
  total: {
    fontWeight: 700,
  }
}));

const products = [
  { name: 'Product 1', desc: 'A nice thing', price: '$9.99' },
  { name: 'Product 2', desc: 'Another thing', price: '$3.45' },
  { name: 'Product 3', desc: 'Something else', price: '$6.51' },
  { name: 'Product 4', desc: 'Best thing of all', price: '$14.11' },
  { name: 'Shipping', desc: '', price: 'Free' },
];

export default function Dashboard() {
  const classes = useStyles();
  const [open, setOpen] = React.useState(false);
  const [cart_count, setCartCount] = React.useState(0)
  const [cart_open, setCartOpen] = React.useState(false);
  const [cart_contents, setCartContent] = React.useState([])

  const history = useHistory()

  const handleCartOpen = () => {
    setCartCount(0)
    setCartOpen(true);
  };

  const handleCartClose = () => {
    setCartOpen(false);
  };
  const handleDrawerOpen = () => {
    setOpen(true)
  };
  const handleDrawerClose = () => {
    setOpen(false)
  };

  const fixedHeightPaper = clsx(classes.paper, classes.fixedHeight);

  React.useEffect(() => {
    getCart(null, (message, severity) => {
        if(severity === 'success'){
          if(Array.isArray(message) && message.length < 1){
            // setValues({...values, message: `There are no cart items.`, severity: 'warning', open: true})
            setCartCount(0)
            setCartContent([])
            return;
          }
          setCartCount(message.length)
          setCartContent(message)

        }
        if(severity === 'error') console.error(message)
        // setValues({...values, message: message, severity: severity, open: true})
    })
  }, [cart_count]);
  
  console.log(cart_contents)

  return (
    <HashRouter>
    <div className={classes.root}>
      <Dialog open={cart_open} onClose={handleCartClose} aria-labelledby="form-dialog-title">
        <DialogTitle id="form-dialog-title">Cart</DialogTitle>
        <DialogContent>
          <DialogContentText>
            These are the items in your cart
          </DialogContentText>
          <List disablePadding>
            {cart_contents.map((item, index) => (
              <ListItem className={classes.listItem} key={index}>
                <ListItemText primary={`${(index+1)} . ${item.album ? item.album : item.song}`} secondary={`Item: ${item.album ? 'Music Album' : 'Song'}`} />
                {/* <Typography variant="body2">{product.price}</Typography> */}

                <IconButton color="secondary" onClick={e => {
                  removeCartItem({id: item.ID}, () => {
                    handleCartOpen()
                  })
                }}>
                  <RemoveShoppingCartIcon />
                  </IconButton>
              </ListItem>
            ))}
          </List>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCartClose} color="primary">
            Close
          </Button>
          {/* <Button color="primary" onClick={e => {
            handleCartClose()
            handleClick()
          }}>
            Checkout
          </Button> */}
        </DialogActions>
      </Dialog>
      <CssBaseline />
      <AppBar position="absolute" className={clsx(classes.appBar, open && classes.appBarShift)}>
        <Toolbar className={classes.toolbar}>
          <IconButton
            edge="start"
            color="inherit"
            aria-label="open drawer"
            onClick={handleDrawerOpen}
            className={clsx(classes.menuButton, open && classes.menuButtonHidden)}
          >
            <MenuIcon />
          </IconButton>
          <Typography component="h1" variant="h6" color="inherit" noWrap className={classes.title}>
            Shopping Cart Application
          </Typography>
          <IconButton color="inherit">
            <Badge badgeContent={cart_count} onClick={handleCartOpen} color="secondary">
              <ShoppingCartIcon />
            </Badge>
          </IconButton>
        </Toolbar>
      </AppBar>
      <Drawer
        variant="permanent"
        classes={{
          paper: clsx(classes.drawerPaper, !open && classes.drawerPaperClose),
        }}
        open={open}
      >
        <div className={classes.toolbarIcon}>
          <IconButton onClick={handleDrawerClose}>
            <ChevronLeftIcon />
          </IconButton>
        </div>
        <Divider />
        {/* <List>{mainListItems}</List> */}
        <List>
          {[
            {name: 'Genres', icon: <HeadsetMicIcon />, url: '/genres'},
            {name: 'Artists', icon: <FaceIcon />, url: '/artists'},
            {name: 'Albums', icon: <AlbumIcon />, url: '/albums'},
            {name: 'Songs', icon: <MusicNoteIcon />, url: '/songs'},
          ].map((item, index) => (
            <Link to={item.url}>
              <ListItem button key={item.name}>
                <ListItemIcon>{item.icon}</ListItemIcon>
                <ListItemText primary={item.name} />
              </ListItem>
            </Link>
          ))}
        </List>
        <Divider />
        {/* <List>{secondaryListItems}</List> */}
        <List>
          {[
            {name: 'Checkout', icon: <ShoppingBasket />, url: '/checkout'},
            // {name: 'Add Data', icon: <StorageIcon />},
          ].map((item, index) => (
            <Link to={item.url}>
            <ListItem button key={item.name}>
              <ListItemIcon>{item.icon}</ListItemIcon>
              <ListItemText primary={item.name} />
            </ListItem>
            </Link>
          ))}
        </List>
      </Drawer>
      <main className={classes.content}>
        <div className={classes.appBarSpacer} />
        <Container maxWidth="lg" className={classes.container}>
          <Route path="/genres" component={Genres} />
          <Route path="/artists" component={Artists} />
          {/* <Route path="/artists/:genre" component={Artists} /> */}
          <Route path="/albums" render={(props) => <Albums setCartCount={setCartCount} {...props} />} />
          {/* <Route path="/albums/:genre/genre" render={(props) => <Albums setCartCount={setCartCount} {...props} />} /> */}
          {/* <Route path="/albums/:artist/artist" render={(props) => <Albums setCartCount={setCartCount} {...props} />} /> */}
          <Route path="/songs" render={(props) => <Songs setCartCount={setCartCount} {...props} />} />
          <Route path="/checkout" render={(props) => <Checkout setCartCount={setCartCount} cart_contents={cart_contents} {...props} />}/>
          <Box pt={4}>
              <Copyright />
            </Box>
        </Container>
      </main>
    </div>
    </HashRouter>
  );
}